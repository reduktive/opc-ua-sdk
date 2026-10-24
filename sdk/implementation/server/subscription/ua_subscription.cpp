// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_subscription.h"

#include "ua_address_space.h"
#include "ua_event_notifier_type.h"
#include "ua_node_accessor.h"
#include "ua_subscription_router.h"
#include "ua_session_security.h"
#include "ua_create_monitored_items_request.h"
#include "ua_diagnostic_bits.h"
#include "ua_data_change_notification.h"
#include "ua_date_time.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_notification_list.h"
#include "ua_event_type_model.h"
#include "ua_refresh_required_event_payload.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_monitored_item_factory.h"
#include "ua_monitoring_entry.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_node_description.h"
#include "ua_numeric_data_type_facts.h"
#include "ua_numeric_range_parser.h"
#include "ua_range.h"
#include "ua_instance_utils.h"
#include "ua_referencetype_id.h"
#include "ua_sample_sink_impl.h"
#include "ua_status_change_notification.h"
#include "ua_node_utilities.h"
#include "ua_on_strand.h"
#include "ua_self_owning_operation.h"
#include "ua_status_routing.h"
#include "ua_service_request_info.h"
#include "ua_subtype_facts.h"
#include "ua_callback_safety.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_utilities.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <utility>
#include <array>
#include <chrono>
#include <cmath>
#include <exception>
#include <limits>
#include <variant>

namespace ua::server
{

namespace
{

/// OPC 10000-4 7.22.2 (Table 146): an AbsoluteDeadband "applies only to Variables with any Number data
/// type". The Part names no status for a request outside that scope; the Server refuses it with
/// Bad_FilterNotAllowed rather than accept a filter it would then evaluate as plain equality, which is
/// not what the client asked for. Percent is governed by the EURange rule instead.
StatusCode absolute_deadband_on_non_numeric_value(const NodeId& nodeId)
{
  return StatusCode{Status::BadFilterNotAllowed,
    ErrorDetail::build("AbsoluteDeadbandOnNonNumericValue",
      "AbsoluteDeadband applies only to Variables whose DataType is a subtype of Number",
      "Subscription")
      .context(ua::ContextKeys::nodeId, ua::to_string(nodeId))};
}

/// The refusal of an item whose lookup the namespace answered Uncertain: the SDK does not create or change
/// monitoring on a Node the namespace is uncertain of, whether or not the answer holds the Node, and a row
/// whose status is not Bad reads to a client as created (Part 4 Table 69), so the row is refused
/// `Bad_InternalError` (`LookupAnswerUncertain`), with the Uncertain status as its cause (DL-69 (D2)).
StatusCode lookup_answer_uncertain(const NodeId& nodeId, const StatusCode& answer)
{
  return server::detail::uncertain_answer_refused(
    server::detail::lookupAnswerUncertain, answer, "Subscription", nodeId);
}

/// Whether a sample held for an item before its create committed is newer than the item's initial value.
/// When both carry a SourceTimestamp, those decide. Otherwise the sample is newer when it reached the strand
/// after the initial value was asked for: @p arrival and @p issued are the strand sequence taken at each.
/// ServerTimestamps cannot decide, because the initial value is stamped at commit, after every held sample.
/// The rule errs towards delivering: a sample the namespace took before the read but posted after it is
/// delivered after an initial value newer than itself, and the newer value's own sample follows it, so the
/// client ends on the right value; a change dropped because the read was thought to have seen it is lost.
bool newer_than_initial(const DataValue& sample, uint64_t arrival,
  const std::optional<DateTime>& initialSourceTimestamp, uint64_t issued)
{
  const auto& sampleTimestamp = sample.source_timestamp();
  if (sampleTimestamp.has_value() && !sampleTimestamp->is_null() && initialSourceTimestamp.has_value() &&
      !initialSourceTimestamp->is_null())
  {
    return *initialSourceTimestamp < *sampleTimestamp;
  }
  return issued < arrival;
}

AccessOperation monitored_item_operation(const MonitoredItem& item)
{
  if (item.isEventItem)
    return AccessOperation::ReceiveEvents;

  const auto attribute = utils::from_underlying<AttributeId>(item.itemToMonitor.attribute_id());
  if (attribute == AttributeId::Value)
    return AccessOperation::Read;
  if (attribute == AttributeId::RolePermissions)
    return AccessOperation::ReadRolePermissions;
  return AccessOperation::Browse;
}

AccessControl::Verdict first_verdict_or_denied(std::vector<AccessControl::Verdict> verdicts)
{
  if (!verdicts.empty())
    return std::move(verdicts.front());
  return AccessControl::Verdict{.cause = StatusCode{Status::BadUserAccessDenied}};
}

StatusCode monitoring_mode_authorization_denied(
  const NodeId& nodeId, std::string code, std::string summary, StatusCode cause)
{
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build(std::move(code), std::move(summary), "Subscription")
      .context(ContextKeys::nodeId, nodeId.as_definition())
      .cause(std::move(cause))};
}

StatusCode monitoring_mode_change_busy()
{
  return StatusCode{Status::BadInvalidState,
    ErrorDetail::build("SetMonitoringModeBusy",
      "A SetMonitoringMode authorization transaction is already active for this Subscription",
      "Subscription")};
}

StatusCode periodic_recheck_denied(
  const NodeId& nodeId, std::string code, std::string summary, StatusCode cause)
{
  if (cause == StatusCode{Status::BadNodeIdUnknown})
  {
    return cause;
  }
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build(std::move(code), std::move(summary), "Subscription")
      .context(ContextKeys::nodeId, nodeId.as_definition())
      .cause(std::move(cause))};
}

/// What a re-evaluation cycle learnt about one item of its snapshot from the batched lookup and the batched
/// authorization, before it applies the verdict.
struct RecheckSubject
{
  IntegerId monitoredItemId{0};
  /// The lookup's answer; a Good answer holds the Node.
  NodeAccessorResult found{StatusCode{Status::BadInternalError}};
  /// The failure of a lookup that threw instead of answering.
  std::optional<StatusCode> lookupThrew;
  /// The failure of an authorization that threw instead of answering.
  std::optional<StatusCode> authorizationThrew;
  AccessControl::Verdict verdict{.cause = StatusCode{Status::BadUserAccessDenied}};
};

StatusCode recheck_lookup_count_mismatch(std::size_t expected, std::size_t actual)
{
  return StatusCode{Status::BadInternalError,
    ErrorDetail::build("AccessRecheckLookupCountMismatch",
      "The lookup of the monitored Nodes answered another number of items than it was asked for",
      "Subscription")
      .context(ContextKeys::expected, std::to_string(expected))
      .context(ContextKeys::actual, std::to_string(actual))};
}

/// The Node an Event's ReceiveEvents permission is tested on in place of its SourceNode. A null SourceNode
/// means the Event is not specific to a Node (OPC 10000-5 6.4.2); the Server Object stands in for it, as it
/// does for the Event types whose SourceNode defaults to it. The delivered Event keeps its null SourceNode.
NodeId receive_events_source_subject(const NodeId& sourceNode)
{
  return sourceNode.is_null() ? NodeId{ObjectId::Server} : sourceNode;
}

StatusCode event_subject_resolution_denied(
  const CompiledEventFilter::AuthorizationSubject& subject, StatusCode cause)
{
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build("EventAuthorizationSubjectUnavailable",
      "An Event authorization subject could not be resolved",
      "Subscription")
      .context(ContextKeys::nodeId, subject.nodeId.as_definition())
      .context(ContextKeys::value, std::to_string(utils::to_underlying(subject.operation)))
      .cause(std::move(cause))};
}

StatusCode event_delivery_deadline_exceeded(uint64_t ordinal)
{
  return StatusCode{Status::BadTimeout,
    ErrorDetail::build("EventAuthorizationDeadlineExceeded",
      "The active Event head did not complete authorization before its fixed deadline",
      "Subscription")
      .context(ContextKeys::index, ordinal)};
}

StatusCode event_delivery_state_unavailable(uint64_t ordinal)
{
  return StatusCode{Status::BadInvalidState,
    ErrorDetail::build("EventDeliveryStateUnavailable",
      "The active Event head no longer has the dependencies required for delivery",
      "Subscription")
      .context(ContextKeys::index, ordinal)};
}

std::optional<SessionAccessControl> current_access_control(
  const MonitoredItem& item, std::chrono::milliseconds authorizationTimeout, Logger logger)
{
  auto securityContext = item.accessSecurityContext.lock();
  if (!securityContext)
    return std::nullopt;
  auto addressSpace = item.accessAddressSpace.lock();
  if (!addressSpace)
    return std::nullopt;
  return SessionAccessControl::create(
    *securityContext, *addressSpace, authorizationTimeout, std::move(logger));
}

/// Gives a value entering a MonitoredItem the ServerTimestamp of its arrival when its source set none
/// (Part 4 7.11). Stamped on the user-independent value, before anything is projected from it, so a
/// Publish, a Republish and a ResendData of the same sample all carry the same ServerTimestamp.
void stamp_received(DataValue& value)
{
  if (const auto& serverTimestamp = value.server_timestamp(); !serverTimestamp || serverTimestamp->is_null())
    value.server_timestamp() = DateTime::now();
}

/// The info bits of a StatusCode, below its severity and subcode (OPC 10000-4 7.39): StructureChanged,
/// SemanticsChanged, the InfoType, the limit bits, Overflow and the historian bits.
constexpr StatusCodeValue statusInfoBits = 0x0000FFFFU;

/// Gives a re-projected retained value the info bits of the status it was @p published with, keeping its own
/// severity, subcode and ErrorDetail (COMP-SVR-NAMESPACE-CALLS-15 rule 4). The bits belong to the
/// notification - its queue overflowed, its semantics changed - not to the projection, which derives the
/// value and its quality again and may replace the status whole: a RolePermissions projection sets Good, and
/// an IndexRange that selects nothing sets Bad_IndexRangeNoData.
void keep_published_info_bits(DataValue& reprojected, const DataValue& published)
{
  const auto& publishedStatus = published.status();
  const StatusCodeValue publishedBits =
    publishedStatus ? publishedStatus.value().value() & statusInfoBits : 0U;
  const StatusCode quality = reprojected.status().value_or(StatusCode{});
  if ((quality.value() & statusInfoBits) == publishedBits)
    return;
  reprojected.status() =
    StatusCode{(quality.value() & ~statusInfoBits) | publishedBits, quality.shared_detail()};
}

DataValue project_monitored_value(
  const MonitoredItem& item, DataValue value, std::chrono::milliseconds authorizationTimeout, Logger logger)
{
  auto accessControl = current_access_control(item, authorizationTimeout, std::move(logger));
  if (!accessControl || !item.accessControlNode || !item.accessSnapshot ||
      !item.access_snapshot_matches(accessControl->identity()->key()))
    return DataValue{StatusCode{Status::BadUserAccessDenied}};
  const auto attribute = utils::from_underlying<AttributeId>(item.itemToMonitor.attribute_id());
  // The item's own NodeId: a value sampled before the Node was deleted is projected after the deletion,
  // when the deleted Node no longer answers its NodeId.
  return accessControl->make_client_attribute_value(item.itemToMonitor.node_id(),
    *item.accessControlNode,
    attribute,
    std::move(value),
    item.accessSnapshot->verdict);
}

bool snapshot_allows_current_identity(const MonitoredItem& item)
{
  if (item.access_denied())
    return false;
  auto securityContext = item.accessSecurityContext.lock();
  if (!securityContext)
    return false;
  const auto identity = securityContext->access_identity();
  return identity && item.access_snapshot_matches(identity->key());
}

DataValue latest_user_independent_value_or_denied(const MonitoredItem& item)
{
  if (item.lastUserIndependentValue)
    return *item.lastUserIndependentValue;
  return DataValue{StatusCode{Status::BadUserAccessDenied}};
}

std::shared_ptr<const event_type_model::DeclarationsResult> retained_declaration_model(
  const std::shared_ptr<const event_type_model::DeclarationsResult>& model)
{
  if (!model)
    return {};
  if (!model->has_value())
  {
    return std::make_shared<const event_type_model::DeclarationsResult>(
      model->status_code(), model->shared_detail());
  }

  auto declarations = model->value();
  for (auto& declaration : declarations)
    declaration.accessor.reset();
  return std::make_shared<const event_type_model::DeclarationsResult>(
    std::move(declarations), model->status_code());
}

size_t retained_data_count(const NotificationMessage& message)
{
  size_t count = 0;
  for (const auto& notification : message.notification_data())
  {
    const auto* dataChange = dynamic_cast<const DataChangeNotification*>(notification.get());
    if (dataChange)
      count += dataChange->monitored_items().size();
  }
  return count;
}

size_t retained_event_count(const NotificationMessage& message)
{
  size_t count = 0;
  for (const auto& notification : message.notification_data())
  {
    const auto* events = dynamic_cast<const EventNotificationList*>(notification.get());
    if (events)
      count += events->events().size();
  }
  return count;
}

void remove_retained_events(NotificationMessage& message)
{
  auto& notificationData = message.notification_data();
  Array<RefStructure<Structure>> retained;
  retained.reserve(notificationData.size());
  for (auto& notification : notificationData)
  {
    if (!dynamic_cast<const EventNotificationList*>(notification.get()))
      retained.push_back(std::move(notification));
  }
  notificationData = std::move(retained);
}

void filter_retained_events(NotificationMessage& message, const std::vector<bool>& permitted)
{
  size_t cursor = 0;
  for (auto& notification : message.notification_data())
  {
    auto* events = dynamic_cast<EventNotificationList*>(notification.get());
    if (!events)
      continue;

    Array<EventFieldList> retained;
    retained.reserve(events->events().size());
    for (auto& event : events->events())
    {
      if (cursor < permitted.size() && permitted[cursor])
        retained.push_back(std::move(event));
      ++cursor;
    }
    events->events() = std::move(retained);
  }

  auto& notificationData = message.notification_data();
  Array<RefStructure<Structure>> retainedNotifications;
  retainedNotifications.reserve(notificationData.size());
  for (auto& notification : notificationData)
  {
    const auto* events = dynamic_cast<const EventNotificationList*>(notification.get());
    if (!events || !events->events().empty())
      retainedNotifications.push_back(std::move(notification));
  }
  notificationData = std::move(retainedNotifications);
}

/// The good handles in one namespace's answer to create_monitoring.
std::vector<IssuedMonitoringHandle> good_handles(
  uint16_t namespaceIndex, const BatchResult<MonitoringCreateItemResult>& answer)
{
  std::vector<IssuedMonitoringHandle> handles;
  if (answer.batchStatus.is_bad())
  {
    return handles;
  }
  for (const auto& item : answer.items)
  {
    if (item.is_good() && item.value().handle != 0)
    {
      handles.push_back(IssuedMonitoringHandle{namespaceIndex, item.value().handle});
    }
  }
  return handles;
}

/// Releases, on every way out of a create's body, the handles of the items it did not commit: a refusal
/// after registration, the create ending early, or the body's frame being destroyed with its Subscription.
/// @tparam PendingItem Subscription::PendingItem, private to it; named only where the Subscription uses this.
template<typename PendingItem>
class UncommittedMonitoringHandles
{
public:
  UncommittedMonitoringHandles(std::vector<PendingItem>& items, WeakAddressSpace addressSpace, Logger logger)
    : mItems(items), mAddressSpace(std::move(addressSpace)), mLogger(std::move(logger))
  {}

  UncommittedMonitoringHandles(const UncommittedMonitoringHandles&) = delete;
  UncommittedMonitoringHandles& operator=(const UncommittedMonitoringHandles&) = delete;
  UncommittedMonitoringHandles(UncommittedMonitoringHandles&&) = delete;
  UncommittedMonitoringHandles& operator=(UncommittedMonitoringHandles&&) = delete;

  ~UncommittedMonitoringHandles()
  {
    try
    {
      std::vector<IssuedMonitoringHandle> handles;
      for (const auto& pending : mItems)
      {
        if (!pending.committed && pending.issuedHandle.handle != 0)
        {
          handles.push_back(pending.issuedHandle);
        }
      }
      release_monitoring_handles(mAddressSpace, std::move(handles), mLogger);
    }
    catch (...)
    {
      ua::detail::ignore_expected_exception();
    }
  }

private:
  std::vector<PendingItem>& mItems;
  WeakAddressSpace mAddressSpace;
  Logger mLogger;
};

}  // namespace

// --- SampleSinkImpl ---

// The three notifications below borrow the OWNING SUBSCRIPTION's lifetime (a weak_ptr sibling, not
// the sink's own), so they use the weak_ptr overload of post_borrowing: each call posts a single
// guarded continuation onto the subscription strand and no-ops if the subscription is gone.
void SampleSinkImpl::push(std::vector<std::pair<IntegerId, DataValue>> samples)
{
  if (mDetached.load(std::memory_order_acquire))
    return;
  ua::async::post_borrowing(mSubscription,
    mSubscriptionStrand,
    mLogger,
    [s = std::move(samples)](Subscription& sub) mutable { sub.on_samples_received(std::move(s)); })();
}

void SampleSinkImpl::invalidate(IntegerId monitoredItemId, StatusCode reason)
{
  if (mDetached.load(std::memory_order_acquire))
    return;
  ua::async::post_borrowing(mSubscription,
    mSubscriptionStrand,
    mLogger,
    [miId = monitoredItemId, reason](Subscription& sub) { sub.on_sample_invalidated(miId, reason); })();
}

void SampleSinkImpl::mark_semantics_changed(IntegerId monitoredItemId)
{
  if (mDetached.load(std::memory_order_acquire))
    return;
  ua::async::post_borrowing(mSubscription,
    mSubscriptionStrand,
    mLogger,
    [miId = monitoredItemId](Subscription& sub) { sub.on_semantics_changed(miId); })();
}

void SampleSinkImpl::mark_structure_changed(IntegerId monitoredItemId)
{
  if (mDetached.load(std::memory_order_acquire))
    return;
  ua::async::post_borrowing(mSubscription,
    mSubscriptionStrand,
    mLogger,
    [miId = monitoredItemId](Subscription& sub) { sub.on_structure_changed(miId); })();
}

void SampleSinkImpl::detach()
{
  mDetached.store(true, std::memory_order_release);
}

std::shared_ptr<const CallerInfo> SampleSinkImpl::caller() const
{
  std::shared_ptr<SessionSecurityContext> securityContext;
  {
    const std::lock_guard lock{mSecurityContextMutex};
    securityContext = mSecurityContext.lock();
  }
  return securityContext ? securityContext->caller() : nullptr;
}

void SampleSinkImpl::set_security_context(std::weak_ptr<SessionSecurityContext> securityContext)
{
  const std::lock_guard lock{mSecurityContextMutex};
  mSecurityContext = std::move(securityContext);
}

// --- Subscription ---

namespace
{

/// A namespace's answer to one monitoring item that holds no result, as that item's result: a Bad answer is
/// the item's; an Uncertain answer without a result leaves the item not created or changed, so it is
/// answered `Bad_InternalError` (`MonitoringAnswerWithoutResult`), with the namespace's answer as the cause.
/// An answer holding a result, Uncertain included, creates or changes the item, which answers its code.
StatusCode refused_monitoring_answer(const StatusCode& answer, const NodeId& nodeId)
{
  if (answer.is_bad())
  {
    return answer;
  }
  try
  {
    return StatusCode{Status::BadInternalError,
      ErrorDetail::build("MonitoringAnswerWithoutResult",
        "The namespace answered the monitoring item Uncertain, which carries no result",
        "Subscription")
        .context(ContextKeys::nodeId, nodeId)
        .cause(answer)};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

class SubscriptionWrapper : public Subscription
{
public:
  SubscriptionWrapper(IntegerId subscriptionId, Duration publishingInterval, uint32_t lifetimeCount,
    uint32_t maxKeepAliveCount, uint32_t maxNotificationsPerPublish, bool publishingEnabled, uint8_t priority,
    boost::asio::any_io_executor executor, NotifyReady onReady, NotifyExpired onExpired,
    SubscriptionRouter::Weak registry, uint32_t maxResponseMessageSize)
    : Subscription(subscriptionId, publishingInterval, lifetimeCount, maxKeepAliveCount,
        maxNotificationsPerPublish, publishingEnabled, priority, std::move(executor), std::move(onReady),
        std::move(onExpired), std::move(registry), maxResponseMessageSize)
  {}
};

/// A range a PercentDeadband can use: both limits known and finite (Part 8 5.6.2 gives a limit that is not
/// known as NaN), the high limit above the low, and their difference finite, since the deadband is a share of
/// it.
bool usable_eu_range(double low, double high) noexcept
{
  return std::isfinite(low) && std::isfinite(high) && high > low && std::isfinite(high - low);
}

}  // namespace

std::shared_ptr<Subscription> Subscription::create(IntegerId subscriptionId, Duration publishingInterval,
  uint32_t lifetimeCount, uint32_t maxKeepAliveCount, uint32_t maxNotificationsPerPublish,
  bool publishingEnabled, uint8_t priority, boost::asio::any_io_executor executor, NotifyReady onReady,
  NotifyExpired onExpired, SubscriptionRouter::Weak registry, std::weak_ptr<Session> owningSession,
  uint32_t maxResponseMessageSize)
{
  auto sub = std::make_shared<SubscriptionWrapper>(subscriptionId,
    publishingInterval,
    lifetimeCount,
    maxKeepAliveCount,
    maxNotificationsPerPublish,
    publishingEnabled,
    priority,
    std::move(executor),
    std::move(onReady),
    std::move(onExpired),
    registry,
    maxResponseMessageSize);

  // Create sample sink after construction (needs shared_ptr to self).
  sub->mSampleSink = std::make_shared<SampleSinkImpl>(sub, sub->mStrand);

  // Initialize the cached info snapshot.
  sub->update_info();

  // RAII registration: register with server-level registry (owning session + the subscription
  // itself, so server-wide diagnostics can read its cross-strand snapshot).
  if (auto router = registry.lock())
  {
    router->register_subscription(subscriptionId, std::move(owningSession), sub);
  }

  // Start the publishing timer.
  sub->start_publishing_timer();

  return sub;
}

Subscription::Subscription(IntegerId subscriptionId, Duration publishingInterval, uint32_t lifetimeCount,
  uint32_t maxKeepAliveCount, uint32_t maxNotificationsPerPublish, bool publishingEnabled, uint8_t priority,
  boost::asio::any_io_executor executor, NotifyReady onReady, NotifyExpired onExpired,
  SubscriptionRouter::Weak registry, uint32_t maxResponseMessageSize)
  : mId(subscriptionId), mLifetimeCounter(lifetimeCount), mPublishingInterval(publishingInterval),
    mLifetimeCount(lifetimeCount), mMaxKeepAliveCount(maxKeepAliveCount),
    mMaxNotificationsPerPublish(maxNotificationsPerPublish), mMaxResponseMessageSize(maxResponseMessageSize),
    mPublishingEnabled(publishingEnabled), mPriority(priority), mExecutor(executor),
    mStrand(boost::asio::make_strand(executor)), mOnReady(std::move(onReady)),
    mOnExpired(std::move(onExpired)), mRegistry(std::move(registry))
{}

void Subscription::set_summary_counters(std::shared_ptr<ServerSummaryCounters> counters)
{
  if (counters && !mSummaryCounters)
  {
    mSummaryCounters = std::move(counters);
  }
}

void Subscription::set_logger(ua::Logger logger)
{
  if (mSampleSink)
  {
    mSampleSink->set_logger(logger.with_category("sample-sink"));
  }
  mLogger = std::move(logger);
}

void Subscription::set_access_control_timeout(std::chrono::milliseconds timeout)
{
  mAccessControlTimeout = timeout;
}

Subscription::~Subscription()
{
  // 7.3 ergonomic-firing: any in-flight callback-canonical flow's user callback
  // is fired exactly once with a shutdown status so the contract holds even when
  // the component is destroyed mid-operation. CL-F pins ~Subscription firing
  // the create's completion with BadSubscriptionIdInvalid.
  fail_create(StatusCode{Status::BadSubscriptionIdInvalid});
  fail_delete(StatusCode{Status::BadSubscriptionIdInvalid});
  fail_modify(StatusCode{Status::BadSubscriptionIdInvalid});
  fail_set_monitoring_mode(StatusCode{Status::BadSubscriptionIdInvalid});

  // The namespace monitoring of every item still held: all of them when close() never ran, and any a
  // create committed after it (close() empties the items, so nothing is released twice).
  release_live_monitoring_handles();
  release_event_bus_registrations();
  if (mUnclaimedHandles)
  {
    mUnclaimedHandles->end();
  }

  // The router is gone once its server is (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01): then there is nothing to
  // leave.
  if (auto router = mRegistry.lock())
  {
    router->unregister_subscription(mId);
    // A Subscription destroyed without close() takes its intervals out of the server-wide tally here.
    if (!mReportedSamplingIntervals.empty())
      router->update_sampling_intervals(mReportedSamplingIntervals, {});
  }
  if (mSampleSink)
  {
    mSampleSink->detach();
  }
  mPublishingTimer.cancel();
  mAccessRecheckTimer.cancel();
  mEventDeliveryDeadlineTimer.cancel();
}

void Subscription::modify(Duration publishingInterval, uint32_t lifetimeCount, uint32_t maxKeepAliveCount,
  uint32_t maxNotificationsPerPublish, uint8_t priority)
{
  mPublishingInterval = publishingInterval;
  mLifetimeCount = lifetimeCount;
  mMaxKeepAliveCount = maxKeepAliveCount;
  mMaxNotificationsPerPublish = maxNotificationsPerPublish;
  mPriority = priority;

  // Reset counters.
  mLifetimeCounter = mLifetimeCount;
  mKeepAliveCounter = mMaxKeepAliveCount;

  start_publishing_timer();
  record_modified();
  update_info();
}

void Subscription::set_publishing_mode(bool enabled)
{
  mPublishingEnabled = enabled;
  // Row 19 ends the MoreNotifications continuation, so the send slot it granted is withdrawn. A Late
  // Subscription also holds a slot its publishing timer granted, and later expiries in Late grant none,
  // so that slot stays: withdrawing it would leave every later Publish unanswered.
  if (mMoreNotificationsContinuationPending && mPublishingState != PublishingState::Late)
  {
    mReadyToPublish = false;
  }
  mMoreNotificationsContinuationPending = false;
  reset_lifetime();
  record_publishing_mode(enabled);
  update_info();
}

void Subscription::on_service_call()
{
  reset_lifetime();
  update_info();
}

void Subscription::release_server_monitored_item_slots()
{
  const std::lock_guard<std::mutex> lock{mSlotMutex};
  if (!mSlots.held)
  {
    return;
  }
  mSlots.held = false;
  if (mSummaryCounters && mSlots.itemCount > 0)
  {
    mSummaryCounters->currentMonitoredItemCount.fetch_sub(mSlots.itemCount, std::memory_order_relaxed);
  }
}

bool Subscription::reacquire_server_monitored_item_slots(std::optional<uint32_t> serverMax)
{
  const std::lock_guard<std::mutex> lock{mSlotMutex};
  if (mSlots.held)
  {
    return true;
  }
  if (mSummaryCounters && mSlots.itemCount > 0)
  {
    auto& gauge = mSummaryCounters->currentMonitoredItemCount;
    if (serverMax)
    {
      // All or nothing, with the same compare-exchange the create gate uses, so concurrent creates
      // and this claim observe each other instead of both racing past a stale load.
      uint32_t cur = gauge.load(std::memory_order_relaxed);
      do
      {
        if (cur >= *serverMax || mSlots.itemCount > *serverMax - cur)
        {
          return false;
        }
      }
      while (!gauge.compare_exchange_weak(
        cur, cur + mSlots.itemCount, std::memory_order_acq_rel, std::memory_order_relaxed));
    }
    else
    {
      gauge.fetch_add(mSlots.itemCount, std::memory_order_relaxed);
    }
  }
  mSlots.held = true;
  return true;
}

void Subscription::account_committed_item(bool reservedInGauge)
{
  const std::lock_guard<std::mutex> lock{mSlotMutex};
  ++mSlots.itemCount;
  if (reservedInGauge && !mSlots.held && mSummaryCounters)
  {
    // The reservation raised the gauge for this item, but a parked orphan holds no slots: hand it
    // straight back, so the item is claimed again (bounded) only when a transfer gives it a session.
    mSummaryCounters->currentMonitoredItemCount.fetch_sub(1, std::memory_order_relaxed);
  }
}

void Subscription::account_deleted_items(
  uint32_t deletedCount, const std::shared_ptr<ServerSummaryCounters>& counters)
{
  const std::lock_guard<std::mutex> lock{mSlotMutex};
  const uint32_t released = std::min(deletedCount, mSlots.itemCount);
  mSlots.itemCount -= released;
  if (mSlots.held && counters && released > 0)
  {
    counters->currentMonitoredItemCount.fetch_sub(released, std::memory_order_relaxed);
  }
}

void Subscription::close()
{
  if (mClosed)
    return;
  mClosed = true;

  // Cancel the publishing timer.
  mPublishingTimer.cancel();
  // Cancel the periodic access-recheck timer (no new cycles; any in-flight cycle drains harmlessly -
  // its continuations re-look-up items by id and find none after mMonitoredItems is cleared below).
  mAccessRecheckTimer.cancel();

  // Detach the sample sink so no more samples arrive.
  if (mSampleSink)
  {
    mSampleSink->detach();
  }

  // Release the remaining items' server-wide slots (exactly the live count; nothing if already
  // released as an orphan).
  release_server_monitored_item_slots();

  if (mAccessRecheckRunning && mAccessRecheckMandatory)
  {
    finish_access_recheck(VoidResult{StatusCode{Status::BadSubscriptionIdInvalid}});
  }
  fail_set_monitoring_mode(StatusCode{Status::BadSubscriptionIdInvalid});

  // The namespaces release what they monitor for these items, and for any create answer still on its way.
  release_live_monitoring_handles();
  if (mUnclaimedHandles)
  {
    mUnclaimedHandles->end();
  }
  release_event_bus_registrations();

  // Clear all monitored items.
  mMonitoredItems.clear();
  mPendingEventDeliveries.clear();
  mPendingEventAccounting.clear();
  mEventDeliveryDeadlineTimer.cancel();
  ++mEventDeliveryAttemptEpoch;
  mActiveEventDeliveryOrdinal = 0;
  mEventDeliveryAccessControl.reset();
  mEventDeliveryPlan.clear();
  mEventDeliveryResolvedItems.clear();
  mEventDeliveryResolvedPlanIndices.clear();
  mEventDeliveryVerdicts.clear();
  mEventDeliveryActive = false;
  mTriggerLinks.clear();
  mReportableItemCount = 0;
  mHasNotifications.store(false, std::memory_order_release);
  mReadyToPublish = false;
  mMoreNotificationsContinuationPending = false;

  // Release callback references to SubscriptionsPipeline.
  mOnReady = nullptr;
  mOnExpired = nullptr;
  update_info();
}

void Subscription::release_live_monitoring_handles() noexcept
{
  try
  {
    std::vector<IssuedMonitoringHandle> handles;
    WeakAddressSpace addressSpace;
    bool haveAddressSpace = false;
    for (const auto& [monitoredItemId, item] : mMonitoredItems)
    {
      (void)monitoredItemId;
      if (!item || item->isEventItem || item->namespaceHandle == 0)
      {
        continue;
      }
      handles.push_back(IssuedMonitoringHandle{item->namespaceIndex, item->namespaceHandle});
      if (!haveAddressSpace)
      {
        addressSpace = item->accessAddressSpace;
        haveAddressSpace = true;
      }
    }
    release_monitoring_handles(addressSpace, std::move(handles), mLogger);
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

void Subscription::release_event_bus_registrations() noexcept
{
  try
  {
    auto bus = mRegisteredEventBus.lock();
    for (auto& [id, item] : mMonitoredItems)
    {
      (void)id;
      if (!item || !item->isEventItem || item->eventBusHandle == 0)
      {
        continue;
      }
      if (bus)
      {
        bus->deregister_event_item(item->eventBusHandle);
      }
      item->eventBusHandle = 0;
    }
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

void Subscription::rewire_callbacks(NotifyReady onReady, NotifyExpired onExpired)
{
  mOnReady = std::move(onReady);
  mOnExpired = std::move(onExpired);
}

void Subscription::resend_initial_values()
{
  for (auto& [miId, item] : mMonitoredItems)
  {
    MonitoredItem& mi = *item;
    if (mi.monitoringMode == MonitoringMode::Reporting && mi.queue.empty() && mi.lastSentValue.has_value())
    {
      const bool hadReportable = mi.has_reportable_notifications();
      auto userIndependentValue = latest_user_independent_value_or_denied(mi);
      auto projected = project_monitored_value(mi, userIndependentValue, mAccessControlTimeout, mLogger);
      mi.enqueue_initial(std::move(projected), std::move(userIndependentValue));
      if (!hadReportable && mi.has_reportable_notifications())
      {
        ++mReportableItemCount;
      }
    }
  }

  if (mReportableItemCount > 0)
  {
    mHasNotifications.store(true, std::memory_order_release);
  }
  update_info();
}

void Subscription::update_registry_owner(std::weak_ptr<Session> newOwner)
{
  if (auto router = mRegistry.lock())
  {
    router->unregister_subscription(mId);
    router->register_subscription(mId, std::move(newOwner), weak_from_this());
  }
}

void Subscription::on_samples_received(std::vector<std::pair<IntegerId, DataValue>> samples)
{
  if (mClosed)
    return;

  for (auto& [miId, value] : samples)
  {
    auto it = mMonitoredItems.find(miId);
    if (it == mMonitoredItems.end())
    {
      // An item of the running create that has not committed yet: the sample is held, and delivered after
      // the item's initial value when it commits (DL-69 (D7)). Bounded like the item's queue.
      if (auto held = mHeldBeforeCommit.find(miId); held != mHeldBeforeCommit.end())
      {
        auto& waiting = held->second;
        if (waiting.samples.size() >= waiting.capacity)
        {
          if (waiting.discardOldest)
            waiting.samples.pop_front();
          else
            waiting.samples.pop_back();
        }
        stamp_received(value);
        waiting.samples.push_back(HeldSample{.arrival = ++mStrandSequence, .value = std::move(value)});
      }
      continue;
    }
    receive_sample(miId, *it->second, std::move(value));
  }
  update_info();
}

void Subscription::receive_sample(IntegerId monitoredItemId, MonitoredItem& item, DataValue value)
{
  // No Session: the Subscription is waiting to be transferred. There is no identity to project for,
  // so the sample is held as it is and replayed through the next owner's authorization.
  if (!item.access_denied() && item.accessSecurityContext.expired())
  {
    const size_t capacity = std::max<size_t>(item.queueSize, 1);
    if (item.orphanedSamples.size() >= capacity)
    {
      if (item.discardOldest)
        item.orphanedSamples.pop_front();
      else
        item.orphanedSamples.pop_back();
    }
    stamp_received(value);
    item.orphanedSamples.push_back(std::move(value));
    return;
  }
  // A denied item remains registered with the sampler for recovery, but real values are dropped.
  // The identity comparison is equally required: after Session identity commit and before its
  // mandatory async refresh completes, an allowed snapshot from the prior identity is unusable.
  if (!snapshot_allows_current_identity(item))
    return;

  accept_sample(monitoredItemId, item, std::move(value));
}

void Subscription::accept_sample(
  IntegerId monitoredItemId, MonitoredItem& item, DataValue userIndependentValue)
{
  stamp_received(userIndependentValue);
  item.lastUserIndependentValue = userIndependentValue;
  auto value = project_monitored_value(item, userIndependentValue, mAccessControlTimeout, mLogger);

  const bool hadNotifications = item.has_reportable_notifications();
  const bool enqueued = item.evaluate_and_enqueue(std::move(value), std::move(userIndependentValue));

  if (enqueued && !hadNotifications && item.has_reportable_notifications())
  {
    ++mReportableItemCount;
  }

  // SVR-MI-GEN-081..087: If this item is a triggering item and it enqueued a notification,
  // mark all linked items as triggered so Sampling-mode items become reportable.
  if (enqueued)
  {
    flush_triggered_links(monitoredItemId);
  }
}

bool Subscription::replay_orphaned_samples(MonitoredItem& item)
{
  // The same gate as a live sample. A snapshot still keyed to the previous Session's identity does not
  // allow the item yet, and the samples wait for the recheck that replaces it (apply_recheck_transition).
  if (item.orphanedSamples.empty() || !snapshot_allows_current_identity(item))
    return false;
  const bool hadNotifications = item.has_reportable_notifications();
  for (auto& sample : std::exchange(item.orphanedSamples, {}))
    accept_sample(item.id, item, std::move(sample));
  return !hadNotifications && item.has_reportable_notifications();
}

void Subscription::replay_orphaned_samples()
{
  bool replayed = false;
  for (auto& [miId, item] : mMonitoredItems)
  {
    (void)miId;
    replayed = replay_orphaned_samples(*item) || replayed;
  }
  if (replayed)
    mHasNotifications.store(true, std::memory_order_release);
  update_info();
}

void Subscription::flush_triggered_links(IntegerId sourceId)
{
  auto linkIt = mTriggerLinks.find(sourceId);
  if (linkIt == mTriggerLinks.end())
    return;

  for (const IntegerId linkedId : linkIt->second)
  {
    auto linkedIt = mMonitoredItems.find(linkedId);
    if (linkedIt == mMonitoredItems.end())
      continue;

    auto& linkedItem = *linkedIt->second;
    const bool linkedHadReportable = linkedItem.has_reportable_notifications();
    linkedItem.triggeredReportPending = true;
    if (!linkedHadReportable && linkedItem.has_reportable_notifications())
    {
      ++mReportableItemCount;
    }
  }
}

void Subscription::on_sample_invalidated(IntegerId monitoredItemId, StatusCode reason)
{
  if (mClosed)
    return;

  auto it = mMonitoredItems.find(monitoredItemId);
  if (it == mMonitoredItems.end())
  {
    // An item of the running create that has not committed yet: the notice, which is sent once, is held and
    // delivered after the item's initial value when it commits (DL-69 (D7)).
    if (auto held = mHeldBeforeCommit.find(monitoredItemId); held != mHeldBeforeCommit.end())
    {
      held->second.notice = reason;
    }
    return;
  }

  // Enqueue a DataValue with the error status code.
  DataValue errorValue;
  errorValue.status() = reason;
  errorValue.source_timestamp() = DateTime::now();

  auto& item = *it->second;
  const bool hadNotifications = item.has_reportable_notifications();
  auto retainedErrorValue = errorValue;
  item.enqueue_initial(std::move(errorValue), std::move(retainedErrorValue));

  const bool enqueued = !hadNotifications || item.has_reportable_notifications();

  if (!hadNotifications && item.has_reportable_notifications())
  {
    ++mReportableItemCount;
  }

  // Trigger linked items (same logic as on_samples_received).
  if (enqueued)
  {
    flush_triggered_links(monitoredItemId);
  }

  update_info();
}

void Subscription::on_semantics_changed(IntegerId monitoredItemId)
{
  if (mClosed)
    return;

  auto it = mMonitoredItems.find(monitoredItemId);
  if (it == mMonitoredItems.end())
  {
    // Registered with its namespace but not yet committed: the mark is applied when it commits.
    if (mCreatingItemIds.contains(monitoredItemId))
    {
      mSemanticMarksBeforeCommit.insert(monitoredItemId);
    }
    return;
  }

  auto& item = *it->second;

  // A PercentDeadband's range follows the EURange Property (Part 8 6.2), which the mark may say changed.
  // Any read already on its way is now older than this mark.
  ++item.euRangeGeneration;
  if (item.deadbandType == DeadbandType::Percent)
  {
    reread_eu_range(item);
  }

  // Arm the item. While armed, every enqueued value carries the SemanticsChanged bit and bypasses
  // the deadband; the flag clears only when a bit-carrying value is actually published, so it
  // survives queue churn until then (MonitoredItem::evaluate_and_enqueue / drain).
  //
  // A second report before that publish is the same change, not another one: one Property write can
  // be reported both by a Data Access semantic Property's write notifier and by the server's
  // SemanticChange handling. The value already queued carries the bit, so nothing more is owed.
  const bool alreadyArmed = item.pendingSemanticChange;
  item.pendingSemanticChange = true;
  if (alreadyArmed && item.has_reportable_notifications())
    return;

  // A value already queued and not yet published is the next DataChange the Client receives, so it is
  // the one that carries the bit - typically the initial value of an item created just before the
  // Property changed. Without this the item would wait, armed, for a sample that a steady value never
  // produces, and the queued value would go out without the bit (the CTT's Data Access Semantic
  // Changes 003).
  if (item.mark_queued_semantics_changed())
  {
    mHasNotifications.store(notifications_available(), std::memory_order_release);
    update_info();
    return;
  }

  // Deliver from the item's cache now. A semantic property changed but the monitored value did not,
  // and the polled sampler only pushes on value *change* (ua_sampling_engine.cpp) - so an armed item
  // whose value is steady would never get a tick to fold the bit into (the CTT 008 case). Synthesizing
  // from the last published value covers polled and exception items alike. With no cache yet, stay
  // armed: the first real value is necessarily a change, so the sampler pushes it and it carries the bit.
  const bool hadReportable = item.has_reportable_notifications();
  if (!item.enqueue_semantic_from_cache())
    return;

  if (!hadReportable && item.has_reportable_notifications())
  {
    ++mReportableItemCount;
  }
  flush_triggered_links(monitoredItemId);

  mHasNotifications.store(notifications_available(), std::memory_order_release);
  update_info();
}

void Subscription::on_structure_changed(IntegerId monitoredItemId)
{
  if (mClosed)
    return;

  auto it = mMonitoredItems.find(monitoredItemId);
  if (it == mMonitoredItems.end())
  {
    // Registered with its namespace but not yet committed: the mark is applied when it commits.
    if (mCreatingItemIds.contains(monitoredItemId))
    {
      mStructureMarksBeforeCommit.insert(monitoredItemId);
    }
    return;
  }

  auto& item = *it->second;
  const bool hadReportable = item.has_reportable_notifications();
  if (!item.mark_structure_changed())
    return;

  // A notification made from the value last published: the Variable's value did not change, so no sample
  // is coming to carry the bit.
  if (!hadReportable && item.has_reportable_notifications())
  {
    ++mReportableItemCount;
  }
  flush_triggered_links(monitoredItemId);

  mHasNotifications.store(notifications_available(), std::memory_order_release);
  update_info();
}

std::vector<Subscription::PublishResult> Subscription::fulfill_publish(uint32_t availablePublishCount)
{
  std::vector<PublishResult> results;
  if (mClosed)
    return results;

  // This dispatch consumes the send slot the publishing timer granted. Close the
  // gate; the moreNotifications branch below re-opens it (via signal_ready) when a
  // single cycle's notifications span multiple responses, and the next timer tick
  // re-opens it for the following cycle. Until then, queued samples wait.
  mReadyToPublish = false;
  mMoreNotificationsContinuationPending = false;

  for (uint32_t i = 0; i < availablePublishCount; ++i)
  {
    const bool hasNotifications = mPublishingEnabled && notifications_available();

    PublishResult result;
    if (hasNotifications)
    {
      result.message = create_notification_message(mMaxNotificationsPerPublish,
        result.dataChangeDiagnosticMasks,
        result.eventProjections,
        result.dataProjections);

      const bool moreRemaining = notifications_available();
      result.moreNotifications = moreRemaining;

      // on_publish_dispatched equivalent
      mMessageSent = true;
      reset_lifetime();

      if (moreRemaining)
      {
        // More notifications remain - signal ready again.
        mMoreNotificationsContinuationPending = true;
        signal_ready();
        mPublishingState = PublishingState::Normal;

        // Second on_publish_dispatched for moreNotifications=true
        mMessageSent = true;
        reset_lifetime();
        signal_ready();
        mPublishingState = PublishingState::Normal;
      }
      else
      {
        // All notifications consumed.
        mPublishingState = PublishingState::Normal;
      }
    }
    else
    {
      // Keep-alive: empty message with peeked sequence number (not incremented).
      result.message.sequence_number() = peek_sequence_number();
      result.message.publish_time() = DateTime::now();
      result.moreNotifications = false;

      // on_publish_dispatched for keep-alive (no notifications, not more)
      mMessageSent = true;
      reset_lifetime();
      mPublishingState = PublishingState::KeepAlive;
      mKeepAliveCounter = mMaxKeepAliveCount;
    }

    results.push_back(std::move(result));
    record_publish_serviced();

    // If this was a keep-alive or no more notifications, stop draining.
    if (!hasNotifications || !results.back().moreNotifications)
      break;
  }

  // Update atomic flag.
  mHasNotifications.store(notifications_available(), std::memory_order_release);
  update_info();

  return results;
}

IntegerId Subscription::add_monitored_item(std::unique_ptr<MonitoredItem> item)
{
  const IntegerId assignedId = mNextMonitoredItemId++;
  item->id = assignedId;

  const bool reportable = item->has_reportable_notifications();
  mMonitoredItems[assignedId] = std::move(item);
  if (reportable)
  {
    ++mReportableItemCount;
  }
  // No create-time reservation raised the gauge on this path (a direct add), so only the live count
  // moves.
  account_committed_item(/*reservedInGauge=*/false);

  update_info();
  return assignedId;
}

bool Subscription::remove_monitored_item(IntegerId monitoredItemId)
{
  auto it = mMonitoredItems.find(monitoredItemId);
  if (it == mMonitoredItems.end())
    return false;

  if (it->second->has_reportable_notifications() && mReportableItemCount > 0)
  {
    --mReportableItemCount;
  }

  // Preserve this item's overflow totals so the subscription's cumulative overflow counts
  // remain monotonic after the item is gone.
  mRemovedDataOverflowCount += it->second->dataQueueOverflowCount;
  mRemovedEventOverflowCount += it->second->eventQueueOverflowCount;

  mMonitoredItems.erase(it);
  // The partner of add_monitored_item's accounting: the live count moves, and the slot is released
  // from the gauge only while this subscription holds its share.
  account_deleted_items(1, mSummaryCounters);

  // Remove any trigger links involving this item.
  mTriggerLinks.erase(monitoredItemId);
  for (auto& [triggering, triggered] : mTriggerLinks)
  {
    triggered.erase(monitoredItemId);
  }

  update_info();
  return true;
}

void Subscription::reread_eu_range(const MonitoredItem& item)
{
  // Every item marked in this strand turn is resolved by one flush, so the marks of many items cost one call
  // of each kind per namespace (NR-62 rule 2). The generation is taken when the flush begins: a mark after
  // that makes the flush's answer stale and schedules the next flush.
  const bool first = mEuRangeRereads.empty();
  mEuRangeRereads.insert(item.id);
  if (first)
  {
    ua::async::post_borrowing(
      this, mStrand, mLogger, [](Subscription& self) { self.flush_eu_range_rereads(); })();
  }
}

void Subscription::flush_eu_range_rereads()
{
  const auto marked = std::exchange(mEuRangeRereads, {});
  std::vector<IntegerId> ids;
  std::vector<uint64_t> generations;
  std::vector<NodeId> variables;
  std::optional<AddressSpace> addressSpace;
  for (const IntegerId monitoredItemId : marked)
  {
    const auto* item = find_monitored_item(monitoredItemId);
    if (!item || item->deadbandType != DeadbandType::Percent)
    {
      continue;  // deleted or modified since the mark: nothing to read
    }
    if (!addressSpace)
    {
      if (auto locked = item->accessAddressSpace.lock())
      {
        addressSpace = *locked;
      }
    }
    ids.push_back(monitoredItemId);
    generations.push_back(item->euRangeGeneration);
    variables.push_back(item->itemToMonitor.node_id());
  }
  if (ids.empty() || !addressSpace)
  {
    return;
  }
  // The answers, posted to this Subscription's strand: each Property's Value, or why it could not be read.
  auto apply = ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [ids, generations](Subscription& self, std::vector<DataValueResult> values)
    {
      for (size_t k = 0; k < ids.size(); ++k)
      {
        self.apply_reread_eu_range(ids[k],
          generations[k],
          k < values.size() ? std::move(values[k]) : DataValueResult{StatusCode{Status::BadInternalError}});
      }
    });
  // The re-read belongs to no request: the server's own. The Variables are looked up again (NR-43 rule 4),
  // and the Property found again by its browse name, because the mark may say it is a new Node (DL-12).
  const auto browseLimit = ua::detail::NodeAccessorRoute::browse_limit(addressSpace->weak());
  namespace_calls::find_nodes(*addressSpace,
    RequestInfo{},
    variables,
    [space = addressSpace->weak(), variables, apply, browseLimit](
      std::vector<NodeAccessorResult> found) mutable
    {
      auto values = std::make_shared<std::vector<DataValueResult>>(
        found.size(), DataValueResult{StatusCode{Status::BadInternalError}});
      std::vector<size_t> resolvedAt;
      std::vector<NodeAccessor> resolved;
      for (size_t k = 0; k < found.size(); ++k)
      {
        if (found[k].is_good())
        {
          resolvedAt.push_back(k);
          resolved.push_back(std::move(found[k]).value());
        }
        else if (found[k].is_bad())
        {
          (*values)[k] = DataValueResult{found[k].status_code()};
        }
        else
        {
          (*values)[k] = DataValueResult{lookup_answer_uncertain(variables[k], found[k].status_code())};
        }
      }
      if (resolved.empty())
      {
        apply(std::move(*values));
        return;
      }
      auto owner = space.lock();
      if (!owner)
      {
        const StatusCode ownerGone = ua::detail::address_space_gone("Subscription");
        for (const std::size_t k : resolvedAt)
        {
          (*values)[k] = DataValueResult{ownerGone};
        }
        apply(std::move(*values));
        return;
      }
      EuRangeResolver::resolve_async(*owner,
        RequestInfo{},
        std::move(resolved),
        browseLimit,
        [values, resolvedAt, apply](std::vector<EuRangeProperty> properties) mutable
        {
          for (size_t r = 0; r < resolvedAt.size() && r < properties.size(); ++r)
          {
            (*values)[resolvedAt[r]] = std::move(properties[r].value);
          }
          apply(std::move(*values));
        });
    });
}

void Subscription::apply_reread_eu_range(
  IntegerId monitoredItemId, uint64_t generation, DataValueResult value)
{
  auto* item = find_monitored_item(monitoredItemId);
  if (!item || item->deadbandType != DeadbandType::Percent || item->euRangeGeneration != generation)
  {
    return;  // deleted, modified, or marked again since the read began: a newer read applies instead
  }
  // A value whose quality is Bad was not read: the read answers its status. The deadband is computed from a
  // Good range only, so a value whose quality is Uncertain is refused.
  if (value.is_good())
  {
    const auto& rangeStatus = value.value().status();
    if (rangeStatus && !rangeStatus.value().is_good())
    {
      value = DataValueResult{server::detail::not_acted_on(
        server::detail::readAnswerUncertain, rangeStatus.value(), "Subscription")};
    }
  }
  const Range* range = value.is_good() ? value.value().value().try_as<Range>() : nullptr;
  if (range && usable_eu_range(range->low(), range->high()))
  {
    item->hasEuRange = true;
    item->euRangeLow = range->low();
    item->euRangeHigh = range->high();
    return;
  }
  // A lookup or read that failed says nothing about the range, unless it found no EURange Property.
  const bool rangeUnknown = !value.is_good() && value.status_code().as_status() != Status::BadNodeIdUnknown;
  if (!rangeUnknown)
  {
    // No usable range: the deadband cannot be computed, so the item reports every change.
    item->hasEuRange = false;
  }
  try
  {
    const std::string status = !value.is_good() ? to_string(value.status_code()) : std::string{"Good"};
    const std::string error = value.shared_detail() ? to_string(*value.shared_detail()) : std::string{};
    auto logger = mLogger.with_category("subscription");
    if (rangeUnknown)
    {
      logger.warning(
        {{"monitored_item_id", std::to_string(monitoredItemId)}, {"status", status}, {"error", error}},
        "A PercentDeadband item's EURange could not be read again; the item keeps the range it holds");
    }
    else
    {
      logger.warning(
        {{"monitored_item_id", std::to_string(monitoredItemId)}, {"status", status}, {"error", error}},
        "A PercentDeadband item's EURange is no longer a usable range; the item reports every change");
    }
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

Result<Subscription::EuRangeRead> Subscription::eu_range_from(const EuRangeProperty& property)
{
  if (!property.value.is_good())
  {
    return property.value.status_code();
  }
  // A value whose quality is Bad was not read: the read answers its status. The deadband is computed from a
  // Good range only, so a value whose quality is Uncertain is refused.
  if (const auto& quality = property.value.value().status(); quality && !quality->is_good())
  {
    return server::detail::not_acted_on(
      server::detail::readAnswerUncertain, *quality, "Subscription", property.property);
  }
  const auto& variant = property.value.value().value();
  const auto* range = (!variant.empty() && variant.is_structure()) ? variant.try_as<Range>() : nullptr;
  if (range == nullptr)
  {
    return StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("EuRangeNotARange", "The EURange Property's Value is not a Range", "Subscription")
        .context(ua::ContextKeys::nodeId, ua::to_string(property.property))};
  }
  return EuRangeRead{range->low(), range->high()};
}

ua::async::Task<std::vector<EuRangeProperty>> Subscription::resolve_eu_ranges(AddressSpace addressSpace,
  RequestInfo request, std::vector<NodeAccessor> variables, std::optional<uint32_t> browseLimit)
{
  if (variables.empty())
  {
    co_return std::vector<EuRangeProperty>{};
  }
  // SVC-10: the Properties and their Values are read asynchronously; the strand is never blocked.
  co_return co_await await_step<std::vector<EuRangeProperty>>(
    [&addressSpace, &request, &variables, &browseLimit](auto completion)
    {
      EuRangeResolver::resolve_async(
        addressSpace, request, std::move(variables), browseLimit, std::move(completion));
    });
}

namespace
{

/// The refusal of a PercentDeadband for @p subject: Part 8 Table 29's Bad_DeadbandFilterInvalid.
///
/// @param readStatus The EURange read's answer: Good when it read a Range whose high bound does not exceed
///                   its low bound; otherwise why it read none, which becomes the refusal's cause.
StatusCode percent_deadband_refusal(const NodeId& subject, const StatusCode& readStatus)
{
  auto detail = ErrorDetail::build("PercentDeadbandWithoutEuRange",
    "PercentDeadband requires a configured EURange whose high bound exceeds its low bound",
    "Subscription");
  detail.context(ua::ContextKeys::nodeId, ua::to_string(subject));
  if (!readStatus.is_good())
  {
    detail.cause(readStatus);
  }
  return StatusCode{Status::BadDeadbandFilterInvalid, std::move(detail)};
}

}  // namespace

MonitoredItem* Subscription::find_monitored_item(IntegerId monitoredItemId)
{
  auto it = mMonitoredItems.find(monitoredItemId);
  return it != mMonitoredItems.end() ? it->second.get() : nullptr;
}

uint32_t Subscription::allocate_sequence_number()
{
  const uint32_t seqNum = mNextSequenceNumber;
  if (mNextSequenceNumber == std::numeric_limits<uint32_t>::max())
    mNextSequenceNumber = 1;
  else
    ++mNextSequenceNumber;
  return seqNum;
}

uint32_t Subscription::peek_sequence_number() const
{
  return mNextSequenceNumber;
}

void Subscription::signal_ready()
{
  mHasNotifications.store(true, std::memory_order_release);

  // The publishing timer (or a Late catch-up / moreNotifications continuation) has
  // granted a send slot this cycle. Open the dispatch gate so
  // select_subscription_for_publish() picks this subscription - covers keep-alive
  // and first-message scenarios where no data items are queued but the subscription
  // still needs to be dispatched. Cleared again once a Publish response consumes it.
  mReadyToPublish = true;
  {
    const std::lock_guard lock(mInfoMutex);
    mCachedInfo.hasNotifications = true;
    mCachedInfo.readyToPublish = true;
  }

  if (mOnReady)
  {
    auto subscriptionId = mId;
    auto onReady = mOnReady;
    onReady(subscriptionId);
  }
}

void Subscription::notify_expired()
{
  if (mOnExpired)
  {
    auto subscriptionId = mId;
    auto onExpired = mOnExpired;
    onExpired(subscriptionId);
  }
}

void Subscription::reset_lifetime()
{
  mLifetimeCounter = mLifetimeCount;
}

void Subscription::start_publishing_timer()
{
  // Cancel any existing timer (e.g. ModifySubscription re-arms with a new interval).
  mPublishingTimer.cancel();

  auto intervalMs = numeric_cast<int64_t>(mPublishingInterval);
  if (intervalMs <= 0)
    intervalMs = 1;

  // schedule_every implements the 16.5 fixed-grid framing rule centrally:
  // late ticks skip slots without phase-shifting the grid. The previous
  // schedule_after + tail-rearm pattern phase-shifted on every late fire.

  mPublishingTimer = Timer::schedule_every(mStrand,
    std::chrono::milliseconds(intervalMs),
    [weak = weak_from_this()](boost::system::error_code ec)
    {
      if (ec)
        return;  // Timer was cancelled.
      if (auto self = weak.lock())
      {
        self->on_publishing_timer_expired();
      }
    });
}

void Subscription::on_publishing_timer_expired()
{
  if (mClosed)
    return;

  const bool publishReqQueued = mPublishReqQueued.load(std::memory_order_acquire);
  const bool notificationsAvailable = this->notifications_available();

  // Part 4, Row 27: decrement only when no Publish requests are queued.
  // When Publish requests are queued, reset the counter instead.
  if (publishReqQueued)
    mLifetimeCounter = mLifetimeCount;
  else if (mLifetimeCounter > 0)
    --mLifetimeCounter;

  if (mLifetimeCounter == 0)
  {
    notify_expired();
    return;
  }

  switch (mPublishingState)
  {
  case PublishingState::Normal:
  {
    // Issue notifications when there is something to send (publishing enabled and notifications
    // available) OR when no message has been sent yet (the first keep-alive obligation). Both
    // conditions take the same action per the publishing state model; otherwise enter KeepAlive.
    if ((mPublishingEnabled && notificationsAvailable) || !mMessageSent)
    {
      signal_ready();
      if (!publishReqQueued)
        enter_late_state();
    }
    else
    {
      mPublishingState = PublishingState::KeepAlive;
      mKeepAliveCounter = mMaxKeepAliveCount;
    }
    break;
  }

  case PublishingState::Late:
    // Already signaled, just restart timer.
    break;

  case PublishingState::KeepAlive:
  {
    if (mPublishingEnabled && notificationsAvailable)
    {
      signal_ready();
      mPublishingState = PublishingState::Normal;
      if (!publishReqQueued)
        enter_late_state();
    }
    else if (mKeepAliveCounter <= 1)
    {
      signal_ready();
      mKeepAliveCounter = mMaxKeepAliveCount;
    }
    else
    {
      --mKeepAliveCounter;
    }
    break;
  }
  }

  // The publishing-timer is now periodic (schedule_every per 16.5). The
  // historical tail-rearm via start_publishing_timer() is gone; the timer
  // delivers the next tick on the fixed grid.
}

NotificationMessage Subscription::create_notification_message(uint32_t maxNotifications,
  std::vector<uint32_t>& dataChangeDiagnosticMasks, std::vector<RetainedEventProjection>& eventProjections,
  std::vector<RetainedDataProjection>& dataProjections)
{
  NotificationMessage message;

  // Allocate sequence number (incremented for real notifications).
  message.sequence_number() = allocate_sequence_number();
  message.publish_time() = DateTime::now();

  // Drain notifications from all reportable monitored items (SVR-SUB-GEN-090, SVR-SUB-GEN-091).
  // Group data-change notifications into DataChangeNotification,
  // event notifications into EventNotificationList (SVR-EVT-NTF-004).
  std::vector<MonitoredItemNotification> dataChangeItems;
  std::vector<MonitoredItem::QueuedEvent> eventItems;

  uint32_t remainingBudget =
    (maxNotifications == 0) ? std::numeric_limits<uint32_t>::max() : maxNotifications;

  for (auto& [miId, item] : mMonitoredItems)
  {
    if (remainingBudget == 0)
      break;

    if (!item->has_reportable_notifications())
    {
      // Spend any stale trigger pulse. A triggering item fires for one publish
      // cycle: it flushes its linked items' *currently queued* notifications and
      // nothing more (Part 4 5.12.1.6). If the trigger fired while a Sampling
      // link had an empty queue, the pulse found nothing to flush and is now
      // spent - it must not grant the link standing permission to report a
      // sample that arrives in some later cycle. Clearing here prevents that
      // over-report. (An empty queue means the item is non-reportable either
      // way, so mReportableItemCount is unaffected.)
      item->triggeredReportPending = false;
      continue;
    }

    if (item->isEventItem)
    {
      const size_t beforeSize = eventItems.size();
      item->drain_events(remainingBudget, eventItems);
      const uint32_t drained = numeric_cast<uint32_t>(eventItems.size() - beforeSize);

      remainingBudget -= drained;
    }
    else
    {
      const size_t beforeSize = dataChangeItems.size();
      item->drain(remainingBudget, dataChangeItems, dataProjections);
      const uint32_t drained = numeric_cast<uint32_t>(dataChangeItems.size() - beforeSize);

      remainingBudget -= drained;

      // The common path is one integer-mask branch, with no allocation and no StatusCode-detail
      // inspection. Diagnostic clients pay the extra scan only for their own eligible items. The
      // vector is allocated lazily on the first notification that has both a requested
      // operation-level field and an ErrorDetail the server could render, then aligned once after
      // the complete drain loop.
      if ((item->diagnosticInfoMask & diag::operationLevelMask) != 0)
      {
        for (size_t index = beforeSize; index < dataChangeItems.size(); ++index)
        {
          const auto& status = dataChangeItems[index].value().status();
          if (!status || !status->shared_detail())
          {
            continue;
          }
          if (dataChangeDiagnosticMasks.size() <= index)
          {
            dataChangeDiagnosticMasks.resize(index + 1, 0);
          }
          dataChangeDiagnosticMasks[index] = item->diagnosticInfoMask;
        }
      }
    }

    // Clear triggered report pending flag after draining.
    item->triggeredReportPending = false;

    // Update reportable count if item queue is now empty.
    if (!item->has_reportable_notifications() && mReportableItemCount > 0)
    {
      --mReportableItemCount;
    }
  }

  if (!dataChangeDiagnosticMasks.empty())
  {
    dataChangeDiagnosticMasks.resize(dataChangeItems.size(), 0);
  }

  // COND-920: If any event monitored item lost a condition event due to overflow,
  // inject a RefreshRequiredEventPayload into the notification list.
  for (auto& [miId, item] : mMonitoredItems)
  {
    if (item->isEventItem && item->refreshRequired && item->eventFilter)
    {
      auto refreshEvent = std::make_shared<RefreshRequiredEventPayload>();
      refreshEvent->eventType = NodeId{ObjectTypeId::RefreshRequiredEventType};
      refreshEvent->sourceNode = NodeId{ObjectId::Server};
      refreshEvent->sourceName = String{"Internal/RefreshRequired"};
      refreshEvent->severity = 500;
      refreshEvent->message =
        LocalizedText{LocaleId{}, String{"ConditionPayload event lost due to queue overflow"}};
      refreshEvent->time = DateTime::now();
      refreshEvent->receiveTime = refreshEvent->time;

      static std::atomic<uint64_t> refreshEventIdCounter{1};
      auto refId = refreshEventIdCounter++;
      refreshEvent->eventId.resize(sizeof(refId));
      std::memcpy(refreshEvent->eventId.data(), &refId, sizeof(refId));

      // RefreshRequired is itself an Event and therefore enters the same ordered asynchronous
      // recipient gate as every live/ConditionRefresh Event. It may appear in the next Publish
      // response; constructing it synchronously here would bypass the complete subject batch.
      enqueue_event_delivery(miId, std::move(refreshEvent), {});
      item->refreshRequired = false;
    }
  }

  // Build notification data array (5.5 grouping).
  if (!dataChangeItems.empty())
  {
    auto dcn = std::make_unique<DataChangeNotification>();
    for (auto& notification : dataChangeItems)
    {
      dcn->monitored_items().push_back(std::move(notification));
    }

    RefStructure<Structure> ref;
    ref.inner_unique_ptr() = std::move(dcn);
    message.notification_data().push_back(std::move(ref));
  }

  // Event notifications grouped into a single EventNotificationList (SVR-EVT-NTF-004).
  if (!eventItems.empty())
  {
    auto enl = std::make_unique<EventNotificationList>();
    eventProjections.reserve(eventItems.size());
    for (auto& event : eventItems)
    {
      enl->events().push_back(std::move(event.fields));
      eventProjections.push_back(std::move(event.projection));
    }

    RefStructure<Structure> ref;
    ref.inner_unique_ptr() = std::move(enl);
    message.notification_data().push_back(std::move(ref));
  }

  record_notifications(
    numeric_cast<uint32_t>(dataChangeItems.size()), numeric_cast<uint32_t>(eventItems.size()));

  return message;
}

void Subscription::update_reportable_count()
{
  uint32_t count = 0;
  for (auto& [monitoredItemId, item] : mMonitoredItems)
  {
    if (item->has_reportable_notifications())
    {
      ++count;
    }
  }
  mReportableItemCount = count;
}

// --- CreateMonitoredItems ---

Subscription::ServerSlotReservation::ServerSlotReservation(
  std::shared_ptr<ServerSummaryCounters> counters, uint32_t slots)
  : mCounters(std::move(counters)), mSlots(slots)
{}

Subscription::ServerSlotReservation::ServerSlotReservation(ServerSlotReservation&& other) noexcept
  : mCounters(std::move(other.mCounters)), mSlots(other.mSlots)
{
  other.mSlots = 0;
}

Subscription::ServerSlotReservation::~ServerSlotReservation()
{
  // Whatever is still held here was claimed for an item that never committed - one refused by its
  // namespace, one whose body gave up partway, one whose body unwound. Releasing it on the way out
  // is what stops a reservation leaking and drifting the server-wide gauge upward for ever, into a
  // permanent BadTooManyMonitoredItems for everybody.
  release_now();
}

void Subscription::ServerSlotReservation::release_now()
{
  if (mCounters && mSlots > 0)
  {
    mCounters->currentMonitoredItemCount.fetch_sub(mSlots, std::memory_order_relaxed);
  }
  mSlots = 0;
}

void Subscription::ServerSlotReservation::hand_one_over()
{
  // The item committed, so the gauge now counts it as a live monitored item rather than as a
  // reservation. Guarded, because the server-wide cap may not be configured at all.
  if (mSlots > 0)
  {
    --mSlots;
  }
}

/// One CreateMonitoredItems, in the order the handler chain walked it.
void Subscription::start_create(CreateInputs inputs)
{
  // A task is EAGER, and a create whose every row fails validation finishes without ever suspending,
  // firing its answer before this returns. @see start_delete
  const uint64_t generation = ++mCreateGeneration;
  auto creation = run_create(std::move(inputs));
  if (mCreateGeneration == generation)
  {
    mCreateTask = std::move(creation);
  }
}

ua::async::Task<> Subscription::run_create(CreateInputs inputs)
{
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise
  // nobody reads. The client's CreateMonitoredItems would go unanswered, `mCreateRunning` would stay
  // latched against every later create and both access rechecks, and the server-wide slots this
  // create reserved would never come back - which is what the reservation's own destructor is for.
  try
  {
    co_await walk_create(inputs);
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the create and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mCreateRunning)
        {
          fail_create(ua::exception_to_status_code(std::current_exception()));
        }
      })();
  }
  co_return;
}

ua::async::Task<> Subscription::walk_create(CreateInputs& inputs)
{
  std::vector<MonitoredItemCreateResult> results(inputs.request.items_to_create().size());
  std::vector<PendingItem> validItems;
  const UncommittedMonitoringHandles<PendingItem> uncommitted{
    validItems, inputs.addressSpace.weak(), mLogger};

  validate_create_items(inputs, results, validItems);
  for (const auto& pending : validItems)
  {
    if (pending.item)
    {
      mCreatingItemIds.insert(pending.item->id);
      mHeldBeforeCommit.try_emplace(pending.item->id,
        HeldBeforeCommit{.capacity = std::max<size_t>(pending.item->queueSize, 1),
          .discardOldest = pending.item->discardOldest});
    }
  }

  co_await compile_create_event_filters(inputs, results, validItems);
  if (!mCreateRunning)
  {
    co_return;
  }

  // The reservation outlives every step below and is handed to items one at a time as they commit.
  auto reservation = apply_create_caps(inputs, results, validItems);

  co_await look_up_create_items(inputs, results, validItems);
  if (!mCreateRunning)
  {
    co_return;
  }

  co_await authorize_create_items(inputs, validItems);
  if (!mCreateRunning)
  {
    co_return;
  }

  co_await refuse_non_numeric_absolute_deadbands(inputs, results, validItems);
  if (!mCreateRunning)
  {
    co_return;
  }

  co_await register_create_items(inputs, results, validItems);
  if (!mCreateRunning)
  {
    co_return;
  }

  co_await establish_create_items(inputs, results, validItems, reservation);
  if (!mCreateRunning)
  {
    co_return;
  }

  finish_create(std::move(results), reservation);
}

void Subscription::validate_create_items(
  CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems)
{
  // Everything that can be decided from the request alone is decided here, in one turn. No I/O: a
  // row that fails validation gets its status now, and a row that survives becomes a PendingItem
  // that owns its MonitoredItem until the item is committed.
  const auto& itemsToCreate = inputs.request.items_to_create();
  const auto timestampsToReturn = inputs.request.timestamps_to_return();
  const auto publishInterval = mPublishingInterval;

  const Duration minSampling = inputs.capabilities.minSupportedSampleRate;
  const Duration maxSampling = 60000;  // practical upper bound; no explicit config
  // Durable subscriptions lift the queue ceiling so clients can buffer large value runs offline
  // (Part 4 5.13.9). Non-durable subscriptions use the configured/default cap.
  const uint32_t configuredMaxQueueSize = inputs.capabilities.maxMonitoredItemsQueueSize.value_or(1000);
  const uint32_t maxQueueSize =
    mDurable ? std::max(configuredMaxQueueSize, inputs.subscriptionLimits.maxDurableMonitoredItemQueueSize)
             : configuredMaxQueueSize;

  // Stash counters for close() to decrement.
  if (inputs.summaryCounters && !mSummaryCounters)
  {
    mSummaryCounters = inputs.summaryCounters;
  }

  for (size_t i = 0; i < itemsToCreate.size(); ++i)
  {
    const MonitoredItemCreateContext context{itemsToCreate[i],
      timestampsToReturn,
      publishInterval,
      maxQueueSize,
      minSampling,
      maxSampling,
      maxQueueSize,
      inputs.subscriptionLimits.defaultEventQueueSize.value_or(50),
      inputs.capabilities.maxSelectClauseParameters.value_or(0),
      inputs.capabilities.maxWhereClauseParameters.value_or(0),
      inputs.subscriptionLimits.maxWhereClauseOperandBytes.value_or(0)};

    auto outcome = validate_and_build_monitored_item(context, mNextMonitoredItemId);

    if (outcome.statusCode.is_bad())
    {
      results[i].status_code() = outcome.statusCode;
      if (outcome.eventFilterResult)
      {
        auto efr = std::make_unique<EventFilterResult>(std::move(*outcome.eventFilterResult));
        results[i].filter_result().inner_unique_ptr() = std::move(efr);
      }
      continue;
    }

    // Reserve the ID (even if namespace registration fails later, we don't reuse IDs).
    ++mNextMonitoredItemId;

    PendingItem pending;
    pending.index = i;
    pending.item = std::move(outcome.item);
    pending.item->diagnosticInfoMask = inputs.request.request_header().return_diagnostics();
    pending.item->accessSecurityContext = inputs.securityContext;
    pending.item->accessAddressSpace = inputs.addressSpace.weak();
    pending.revisedSamplingInterval = outcome.revisedSamplingInterval;
    pending.revisedQueueSize = outcome.revisedQueueSize;
    pending.eventFilterResult = std::move(outcome.eventFilterResult);
    if (pending.item->isEventItem)
    {
      const auto& filterRef = itemsToCreate[i].requested_parameters().filter();
      if (const auto* eventFilter = dynamic_cast<const EventFilter*>(filterRef.inner_unique_ptr().get()))
        pending.sourceEventFilter = *eventFilter;
    }
    validItems.push_back(std::move(pending));
  }
}

ua::async::Task<> Subscription::compile_create_event_filters(
  CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems)
{
  // An EventFilter's select clauses name BrowsePaths into EventTypes, and whether those paths exist is a
  // question for the address space. Every event item's filter is resolved in ONE call, for the request, so
  // each EventType the filters name is collected once (NR-28 rule 3). Then each item is compiled with its own
  // models, in request order; a filter that fails REMOVES its row from the walk.
  std::vector<EventFilter> filters;
  for (const auto& pending : validItems)
  {
    if (pending.item && pending.sourceEventFilter)
    {
      filters.push_back(*pending.sourceEventFilter);
    }
  }
  if (filters.empty())
  {
    co_return;
  }

  auto models = co_await await_step<std::vector<event_type_model::SelectClauseModelsResult>>(
    [&inputs, &filters](auto completion)
    {
      event_type_model::resolve_select_clause_models_async(
        inputs.addressSpace, inputs.requestInfo, std::move(filters), std::move(completion));
    });
  if (!mCreateRunning)
  {
    co_return;
  }

  // The answers are in the order the filters were sent: the event items in walk order, which nothing changes
  // while the call runs. An empty answer means the answers could not be allocated.
  const event_type_model::SelectClauseModelsResult unanswered{StatusCode{Status::BadOutOfMemory}};
  size_t answer = 0;
  for (size_t cursor = 0; cursor < validItems.size();)
  {
    auto& pending = validItems[cursor];
    if (!pending.item || !pending.sourceEventFilter)
    {
      ++cursor;
      continue;
    }

    const auto& modelResult = answer < models.size() ? models[answer] : unanswered;
    ++answer;
    if (!modelResult.is_good())
    {
      results[pending.index].status_code() = StatusCode{Status::BadMonitoredItemFilterInvalid,
        ErrorDetail::build("EventFilterTypeModelUnavailable",
          "The EventFilter BrowsePath could not be validated against the EventType model",
          "Subscription")
          .cause(modelResult.status_code())};
      validItems.erase(validItems.begin() + numeric_cast<std::ptrdiff_t>(cursor));
      continue;
    }

    const EventFilterCompileLimits limits{
      .maxSelectClauses = inputs.capabilities.maxSelectClauseParameters.value_or(0),
      .maxWhereClauseElements = inputs.capabilities.maxWhereClauseParameters.value_or(0),
      .maxWhereClauseOperandBytes = inputs.subscriptionLimits.maxWhereClauseOperandBytes.value_or(0)};
    std::vector<StatusCode> modelStatuses;
    std::vector<std::optional<NodeAccessor>> modelDeclarations;
    modelStatuses.reserve(modelResult.value().size());
    modelDeclarations.reserve(modelResult.value().size());
    for (const auto& model : modelResult.value())
    {
      modelStatuses.push_back(model.status);
      modelDeclarations.push_back(model.declarationAccessor);
    }
    auto recompiled =
      CompiledEventFilter::compile(*pending.sourceEventFilter, limits, modelStatuses, modelDeclarations);
    pending.eventFilterResult = std::move(recompiled.filterResult);
    if (recompiled.overallStatus.is_bad())
    {
      results[pending.index].status_code() = recompiled.overallStatus;
      auto filterResult = std::make_unique<EventFilterResult>(std::move(*pending.eventFilterResult));
      results[pending.index].filter_result().inner_unique_ptr() = std::move(filterResult);
      validItems.erase(validItems.begin() + numeric_cast<std::ptrdiff_t>(cursor));
      continue;
    }

    pending.item->eventFilter = std::move(recompiled.filter);
    pending.sourceEventFilter.reset();
    ++cursor;
  }
}

Subscription::ServerSlotReservation Subscription::apply_create_caps(
  CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems)
{
  // Apply the per-subscription cap only after asynchronous EventType-model validation. A filter
  // rejected by that validation is not a live MonitoredItem and must not consume a batch slot or
  // cause a later valid request to be refused. Preserve request ordering by rejecting the tail.
  if (inputs.capabilities.maxMonitoredItemsPerSubscription)
  {
    const uint32_t subscriptionMax = *inputs.capabilities.maxMonitoredItemsPerSubscription;
    const uint32_t currentCount = numeric_cast<uint32_t>(mMonitoredItems.size());
    const size_t granted =
      currentCount >= subscriptionMax
        ? 0u
        : std::min(validItems.size(), static_cast<size_t>(subscriptionMax - currentCount));
    for (size_t cursor = granted; cursor < validItems.size(); ++cursor)
    {
      results[validItems[cursor].index].status_code() = StatusCode{Status::BadTooManyMonitoredItems,
        ErrorDetail::build(
          "TooManyMonitoredItems", "Per-subscription monitored-item limit reached", "Subscription")
          .context(ua::ContextKeys::limit, std::to_string(subscriptionMax))
          .context(ua::ContextKeys::countTotal, std::to_string(currentCount + granted))
          .context(ua::ContextKeys::subscriptionId, std::to_string(mId))};
    }
    validItems.resize(granted);
  }

  // Server-wide MaxMonitoredItems gate. Claim slots for the whole batch ATOMICALLY (bounded
  // compare-and-add) so that concurrent CreateMonitoredItems bodies on other subscriptions/sessions
  // - which share this one ServerSummaryCounters - observe each other's reservations instead of all
  // racing past a stale load(). (The previous load-only check let N pipelined batches each read the
  // same pre-increment count and collectively overshoot the cap by up to MaxSubscriptions x
  // MaxMonitoredItemsPerSubscription.) Reserved slots are handed over as items commit, and the
  // residue is released by the reservation itself when the body ends.
  if (inputs.summaryCounters && inputs.capabilities.maxMonitoredItems)
  {
    const uint32_t serverMax = *inputs.capabilities.maxMonitoredItems;
    const auto want = numeric_cast<uint32_t>(validItems.size());
    auto& gauge = inputs.summaryCounters->currentMonitoredItemCount;
    uint32_t cur = gauge.load(std::memory_order_relaxed);
    uint32_t granted = 0;
    do
    {
      granted = (cur >= serverMax) ? 0u : std::min(want, serverMax - cur);
    }
    while (granted > 0 && !gauge.compare_exchange_weak(
                            cur, cur + granted, std::memory_order_acq_rel, std::memory_order_relaxed));

    // Owned from the instant it exists. The gauge has just been raised, and everything below here -
    // building an ErrorDetail for each rejected row, resizing a vector - can allocate and therefore
    // throw. A claim that is not yet owned when that happens is a claim nobody will ever give back.
    ServerSlotReservation reservation{inputs.summaryCounters, granted};

    if (granted < want)
    {
      // Reject the items that did not fit under the server-wide cap (the tail of validItems).
      for (size_t k = granted; k < validItems.size(); ++k)
      {
        results[validItems[k].index].status_code() = StatusCode{Status::BadTooManyMonitoredItems,
          ErrorDetail::build(
            "TooManyMonitoredItems", "Server-wide monitored-item limit reached", "Subscription")
            .context(ua::ContextKeys::limit, std::to_string(serverMax))
            .context(ua::ContextKeys::countTotal, std::to_string(cur))
            .context(ua::ContextKeys::subscriptionId, std::to_string(mId))};
      }
      validItems.resize(granted);
    }

    return reservation;
  }

  if (inputs.summaryCounters)
  {
    // No server-wide cap: nothing to refuse, but the gauge still counts every live item (the summary
    // diagnostics read it, and every later release - delete, orphan, close - subtracts from it), so
    // the reservation raises it exactly as the capped path does.
    const auto want = numeric_cast<uint32_t>(validItems.size());
    inputs.summaryCounters->currentMonitoredItemCount.fetch_add(want, std::memory_order_relaxed);
    return ServerSlotReservation{inputs.summaryCounters, want};
  }
  return ServerSlotReservation{};
}

ua::async::Task<> Subscription::look_up_create_items(
  CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems)
{
  // Every item's Node is looked up ONCE, data and event items together, with one call per namespace through
  // the form that takes the request (NR-26 step 1). Each later step - authorization, the DataType facts,
  // registration, the EURange, the initial value, the EventNotifier - uses what this found.
  std::vector<size_t> subjects;
  std::vector<NodeId> nodeIds;
  subjects.reserve(validItems.size());
  nodeIds.reserve(validItems.size());
  for (size_t cursor = 0; cursor < validItems.size(); ++cursor)
  {
    if (validItems[cursor].item)
    {
      subjects.push_back(cursor);
      nodeIds.push_back(validItems[cursor].item->itemToMonitor.node_id());
    }
  }
  if (subjects.empty())
  {
    co_return;
  }

  // One answer per NodeId, in order: the batched call answers every item, a failed batch included.
  auto found = co_await await_step<std::vector<NodeAccessorResult>>(
    [&inputs, &nodeIds](auto completion) {
      namespace_calls::find_nodes(inputs.addressSpace, inputs.requestInfo, nodeIds, std::move(completion));
    });

  if (!mCreateRunning)
  {
    co_return;
  }

  for (size_t k = 0; k < subjects.size(); ++k)
  {
    auto& pending = validItems[subjects[k]];
    if (!pending.item)
    {
      continue;
    }
    if (k < found.size() && found[k].is_good())
    {
      pending.subject = std::move(found[k]).value();
      continue;
    }
    // Part 4 5.12.2.1: "Servers should return all other errors as CreateMonitoredItems results". A Node that
    // cannot be looked up cannot be authorized or registered, for data and event items alike (DL-69 (D2) as
    // revised): a Bad answer is the row's result with its ErrorDetail; an Uncertain answer holds no Node.
    const StatusCode answer =
      k < found.size() ? found[k].status_code() : StatusCode{Status::BadInternalError};
    results[pending.index].status_code() =
      answer.is_bad() ? answer : lookup_answer_uncertain(pending.item->itemToMonitor.node_id(), answer);
    pending.item.reset();
  }
}

ua::async::Task<> Subscription::authorize_create_items(
  CreateInputs& inputs, std::vector<PendingItem>& validItems)
{
  // Part 4 5.12.2.1: a denied item is NOT rejected. It is created, and carries BadUserAccessDenied
  // on its initial notification instead. So what this walk produces is a snapshot on the item, not a
  // result on the row.
  if (!inputs.accessControl)
  {
    co_return;
  }

  // Every item the lookup found is decided in ONE call, because no item's question depends on another
  // item's answer.
  //
  // Which answer belongs to which item is its POSITION, so the answer is checked for cardinality before it is
  // believed: a collaborator that returns the wrong number would otherwise shift every permission decision
  // onto the wrong item, which is the one mistake this walk must not make.
  std::vector<size_t> decided;
  std::vector<AccessControl::Item> authorizationItems;
  decided.reserve(validItems.size());
  authorizationItems.reserve(validItems.size());
  for (size_t cursor = 0; cursor < validItems.size(); ++cursor)
  {
    auto& pending = validItems[cursor];
    if (!pending.item || !pending.subject)
    {
      continue;
    }
    pending.item->accessControlNode = *pending.subject;
    decided.push_back(cursor);
    authorizationItems.push_back(
      AccessControl::Item{.node = *pending.subject, .operation = monitored_item_operation(*pending.item)});
  }

  if (authorizationItems.empty())
  {
    co_return;
  }

  auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
    [&inputs, &authorizationItems](auto completion) {
      inputs.accessControl->authorize_async(inputs.requestInfo, authorizationItems, std::move(completion));
    });

  if (!mCreateRunning || !inputs.accessControl)
  {
    co_return;
  }

  const auto identityKey = inputs.accessControl->identity()->key();
  for (size_t k = 0; k < decided.size(); ++k)
  {
    const size_t cursor = decided[k];
    if (!validItems[cursor].item)
    {
      continue;
    }
    // One verdict per decided item, taken by position. A short or long answer is not trusted for
    // any of them: `first_verdict_or_denied` on an empty list is what the chain this replaces did
    // with an answer it could not use, and it denies.
    std::vector<AccessControl::Verdict> one;
    if (verdicts.size() == decided.size())
    {
      one.push_back(std::move(verdicts[k]));
    }
    validItems[cursor].item->accessSnapshot =
      MonitoredAccessSnapshot{identityKey, first_verdict_or_denied(std::move(one))};
  }
}

ua::async::Task<> Subscription::refuse_non_numeric_absolute_deadbands(
  CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems)
{
  // OPC 10000-4 7.22.2: an AbsoluteDeadband applies only to Variables with a Number DataType. Decided here,
  // before registration, so a refused row is never registered (NR-26 step 2a); once per distinct DataType of
  // the request. The NodeClass and the DataType come from the Variable's description. A Node that is not a
  // Variable, and one that declares no DataType or BaseDataType, are not refused: an undecidable type may
  // hold numbers.
  std::vector<size_t> rows;
  std::vector<size_t> rowType;
  std::vector<NodeId> types;
  std::map<NodeId, size_t> typeSlot;
  for (size_t cursor = 0; cursor < validItems.size(); ++cursor)
  {
    const auto& pending = validItems[cursor];
    if (!pending.item || pending.item->isEventItem || pending.item->deadbandType != DeadbandType::Absolute ||
        !pending.subject)
    {
      continue;
    }
    const auto nodeDescription = ua::detail::NodeAccessorRoute::attributes(*pending.subject);
    if (!nodeDescription.is_good() || nodeDescription.value().node_class() != NodeClass::Variable)
    {
      continue;
    }
    const NodeId* dataType = nodeDescription.value().data_type();
    if (dataType == nullptr || dataType->is_null())
    {
      continue;
    }
    const auto [entry, added] = typeSlot.try_emplace(*dataType, types.size());
    if (added)
    {
      types.push_back(*dataType);
    }
    rows.push_back(cursor);
    rowType.push_back(entry->second);
  }
  if (rows.empty())
  {
    co_return;
  }

  const auto nonNumeric =
    co_await decide_numeric_data_types(inputs.addressSpace, inputs.requestInfo, std::move(types));
  if (!mCreateRunning)
  {
    co_return;
  }

  for (size_t r = 0; r < rows.size(); ++r)
  {
    auto& pending = validItems[rows[r]];
    if (!pending.item || rowType[r] >= nonNumeric.size() || !nonNumeric[rowType[r]])
    {
      continue;
    }
    results[pending.index].status_code() =
      absolute_deadband_on_non_numeric_value(pending.item->itemToMonitor.node_id());
    pending.item.reset();
  }
}

ua::async::Task<std::vector<bool>> Subscription::decide_numeric_data_types(
  AddressSpace addressSpace, RequestInfo request, std::vector<NodeId> types)
{
  if (types.empty())
  {
    co_return std::vector<bool>{};
  }
  co_return co_await await_step<std::vector<bool>>([&addressSpace, &request, &types](auto completion)
    { numeric_data_type_facts(addressSpace, request, std::move(types), std::move(completion)); });
}

ua::async::Task<> Subscription::register_create_items(
  CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems)
{
  // Group valid data-change items by namespace. Event items skip namespace
  // registration - they bind to EventBus during the establish walk instead.
  std::map<uint16_t, std::vector<std::pair<size_t, MonitoringCreateItem>>> byNamespace;
  for (size_t vi = 0; vi < validItems.size(); ++vi)
  {
    auto& pending = validItems[vi];
    // Event items bind to EventBus later, not to the namespace sampler.
    // Subscribe-denied items ARE still registered here, so that an access recheck that allows them later
    // finds them sampling - but they ignore the real samples that registration produces; see the
    // complete-snapshot guard in receive_sample.
    if (!pending.item || pending.item->isEventItem)
    {
      continue;
    }

    auto nsIndex = pending.item->namespaceIndex;
    MonitoringCreateItem createItem;
    createItem.nodeId = pending.item->itemToMonitor.node_id();
    // The Node the create's lookup found (NR-43 rule 7).
    createItem.node = ua::detail::NodeAccessorRoute::node_of(pending.subject.value());
    const auto clientAttribute =
      utils::from_underlying<AttributeId>(pending.item->itemToMonitor.attribute_id());
    createItem.attributeId = AccessControl::user_independent_attribute(clientAttribute);
    // The namespace narrows what it delivers to the item's range, except for an Attribute whose value the
    // server produces: that registers the Attribute the namespace holds with no range, and the item narrows
    // the value it projects (NR-14 rule 2, DL-69 (D3)).
    if (!AccessControl::produces_value(clientAttribute))
    {
      createItem.indexRange = pending.item->itemToMonitor.index_range();
    }
    createItem.monitoredItemId = pending.item->id;
    createItem.samplingInterval = pending.revisedSamplingInterval;
    createItem.queueSize = pending.item->queueSize;
    createItem.sink = mSampleSink;

    byNamespace[nsIndex].emplace_back(vi, std::move(createItem));
  }

  // Every namespace is asked at once, so the create waits for its slowest namespace rather than for
  // the sum of them. Each part writes only its own items' rows.
  std::vector<ua::async::Task<>> units;
  units.reserve(byNamespace.size());
  for (auto& [namespaceIndex, nsItems] : byNamespace)
  {
    units.push_back(register_in_namespace(inputs, namespaceIndex, nsItems, results, validItems));
  }
  for (auto& unit : units)
  {
    co_await std::move(unit);
  }
}

ua::async::Task<> Subscription::register_in_namespace(CreateInputs& inputs, uint16_t namespaceIndex,
  std::vector<std::pair<size_t, MonitoringCreateItem>>& nsItems,
  std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems)
{
  BatchResult<MonitoringCreateItemResult> batch;
  auto ns = inputs.addressSpace.namespace_array().get_namespace(namespaceIndex);
  if (!ns)
  {
    // Namespace not found - every item in it inherits BadNodeIdUnknown, by the same route a
    // namespace that answered badly would take.
    batch.batchStatus = StatusCode{Status::BadNodeIdUnknown};
  }
  else
  {
    // The namespace views this storage until it answers, which may be after this body has gone; the
    // answer's capture keeps it.
    auto createItems = std::make_shared<std::vector<MonitoringCreateItem>>();
    createItems->reserve(nsItems.size());
    for (const auto& nsItem : nsItems)
    {
      createItems->push_back(nsItem.second);
    }

    // The answer's handles are held from the namespace's own thread before it is posted, so they are
    // released even when this Subscription ends before the post runs.
    if (!mUnclaimedHandles)
    {
      mUnclaimedHandles = std::make_shared<UnclaimedMonitoringHandles>(mLogger);
    }
    auto unclaimed = mUnclaimedHandles;
    const auto ticket = unclaimed->open_ticket();

    // Should this body be torn down before it claims the ticket (another part of the create threw), what the
    // namespace answered, or answers later, is released.
    struct TicketGuard
    {
      TicketGuard(std::shared_ptr<UnclaimedMonitoringHandles> initialHolder, uint64_t initialTicket) noexcept
        : holder(std::move(initialHolder)), ticket(initialTicket)
      {}

      TicketGuard(const TicketGuard&) = delete;
      TicketGuard& operator=(const TicketGuard&) = delete;
      TicketGuard(TicketGuard&&) = delete;
      TicketGuard& operator=(TicketGuard&&) = delete;

      std::shared_ptr<UnclaimedMonitoringHandles> holder;
      uint64_t ticket;
      bool claimed{false};

      ~TicketGuard()
      {
        if (!claimed)
        {
          holder->abandon(ticket);
        }
      }
    } ticketGuard{unclaimed, ticket};

    const auto weakAddressSpace = inputs.addressSpace.weak();
    // The subscription's current caller (NR-49 rule 5), held until the namespace's member returns.
    const auto caller = mSampleSink->caller();
    {
      // The entry guards the call (NR-45 rule 3): its answer is a Bad batch status or one result per item,
      // and it answers once; a throw, a second answer and an answer of the wrong size are answered or
      // released there.
      batch = co_await await_step<BatchResult<MonitoringCreateItemResult>>(
        [&ns,
          &inputs,
          &caller,
          createItems,
          unclaimed,
          ticket,
          weakAddressSpace,
          namespaceIndex,
          logger = mLogger](auto completion)
        {
          ua::detail::MonitoringEntry::create(
            ns,
            inputs.requestInfo,
            caller.get(),
            *createItems,
            [createItems,
              unclaimed,
              ticket,
              weakAddressSpace,
              namespaceIndex,
              completion = std::move(completion)](BatchResult<MonitoringCreateItemResult> answer) mutable
            {
              // Only the call's first answer resumes the create; a later one, which hold() releases, is
              // dropped.
              bool first = true;
              try
              {
                first = unclaimed->hold(ticket, weakAddressSpace, good_handles(namespaceIndex, answer));
              }
              catch (...)
              {
                // Not held: the create still resumes, and claims nothing for this namespace.
                ua::detail::ignore_expected_exception();
              }
              if (first)
              {
                completion(std::move(answer));
              }
            },
            // An answer the entry does not hand on: its handles are released later, so the namespace is not
            // called back from inside its own answer.
            [weakAddressSpace, namespaceIndex, logger](BatchResult<MonitoringCreateItemResult> dropped)
            {
              try
              {
                post_release_monitoring_handles(
                  weakAddressSpace, good_handles(namespaceIndex, dropped), logger);
              }
              catch (...)
              {
                ua::detail::ignore_expected_exception();
              }
            });
        });
    }

    {
      auto claimed = unclaimed->claim(ticket);
      ticketGuard.claimed = true;
      if (!mCreateRunning)
      {
        // The create ended while this namespace answered: none of these items will commit.
        if (claimed)
        {
          release_monitoring_handles(weakAddressSpace, std::move(*claimed), mLogger);
        }
        co_return;
      }
      if (!claimed)
      {
        // The Subscription was closed while this namespace answered, and the close released the handles.
        batch.items.clear();
        batch.batchStatus = StatusCode{Status::BadSubscriptionIdInvalid};
      }
    }
  }

  // Whole-batch failure: every item in this namespace inherits the batch status
  // (propagates source `shared_detail()` via the result's status code).
  if (batch.batchStatus.is_bad())
  {
    for (const auto& nsItem : nsItems)
    {
      const auto vi = nsItem.first;
      results[validItems[vi].index].status_code() = batch.batchStatus.status_code();
      validItems[vi].item.reset();
    }
    co_return;
  }

  // The entry answered one result per item.
  auto& nsResults = batch.items;
  for (size_t j = 0; j < nsItems.size() && j < nsResults.size(); ++j)
  {
    const auto vi = nsItems[j].first;
    const auto resultIdx = validItems[vi].index;
    auto& nsResult = nsResults[j];

    if (!nsResult.has_value())
    {
      results[resultIdx].status_code() =
        refused_monitoring_answer(nsResult.status_code(), validItems[vi].item->itemToMonitor.node_id());
      validItems[vi].item.reset();
    }
    else
    {
      // A Good subcode or an Uncertain code with a result creates the item, which answers that code.
      validItems[vi].answered = nsResult.status_code();
      const auto& success = nsResult.value();
      validItems[vi].item->namespaceHandle = success.handle;
      validItems[vi].issuedHandle = IssuedMonitoringHandle{namespaceIndex, success.handle};
      if (success.revisedSamplingInterval > 0)
      {
        validItems[vi].item->samplingInterval = success.revisedSamplingInterval;
        validItems[vi].revisedSamplingInterval = success.revisedSamplingInterval;
      }
    }
  }
}

ua::async::Task<> Subscription::establish_create_items(CreateInputs& inputs,
  std::vector<MonitoredItemCreateResult>& results, std::vector<PendingItem>& validItems,
  ServerSlotReservation& reservation)
{
  // Each surviving item gets what it needs to start reporting: an EventBus registration for an event item,
  // and for a data-change item the initial value its first notification carries (Part 4 7.25.2).
  //
  // The namespace calls are made first, all at once (NR-26 step 4): the PercentDeadband items' EURanges and
  // the Variables' initial Values, one call of each kind per namespace. Then the items are established and
  // committed in request order, in one strand turn, so the order in which they are committed and queued is
  // the request's.
  std::vector<std::optional<size_t>> euRangeSlot(validItems.size());
  std::vector<std::optional<size_t>> valueSlot(validItems.size());
  std::vector<NodeAccessor> percentVariables;
  std::vector<ua::detail::ValueRead> valueReads;
  for (size_t cursor = 0; cursor < validItems.size(); ++cursor)
  {
    auto& pending = validItems[cursor];
    if (!pending.item || pending.item->isEventItem)
    {
      continue;
    }
    // A PercentDeadband on a node with no usable EURange is REFUSED. OPC 10000-8 Table 29 names this case
    // exactly - Bad_DeadbandFilterInvalid is "the specified PercentDeadband is not between 0.0 and 100.0 OR A
    // PERCENTDEADBAND IS NOT SUPPORTED, SINCE AN EURANGE IS NOT CONFIGURED" - and section 6.2 says the filter
    // "applies only to AnalogItems with an EURange Property". Read after registration, with the initial
    // value, so a change of the EURange from here on reaches the item as a SemanticsChanged mark, applied at
    // commit if it comes first (NR-62).
    // Every item still live holds its Node: the lookup refused every item it found none for.
    const NodeAccessor& subject = pending.subject.value();
    if (pending.item->deadbandType == DeadbandType::Percent)
    {
      euRangeSlot[cursor] = percentVariables.size();
      percentVariables.push_back(subject);
    }
    if (pending.item->access_denied())
    {
      continue;
    }
    const auto attributeId = utils::from_underlying<AttributeId>(pending.item->itemToMonitor.attribute_id());
    if (AccessControl::user_independent_attribute(attributeId) == AttributeId::Value &&
        subject.get_node_class() == NodeClass::Variable)
    {
      // Read with the item's IndexRange, as its samples are: the namespace narrows the Value, the route fails
      // a Value larger than the range, and the item checks it rather than narrowing it again
      // (COMP-ADDRSP-ACCESSOR-ROUTE-05 item 1, COMP-SVR-NAMESPACE-CALLS-15 rule 2).
      ReadValueId initialRead;
      initialRead.node_id() = pending.item->itemToMonitor.node_id();
      initialRead.attribute_id() = pending.item->itemToMonitor.attribute_id();
      initialRead.index_range() = pending.item->itemToMonitor.index_range();
      valueSlot[cursor] = valueReads.size();
      valueReads.push_back(ua::detail::ValueRead{subject, std::move(initialRead)});
    }
  }

  // For the Session the items sample for. A node whose Value differs per caller produces the initial value
  // for this caller; everything else ignores it. A context that gives no caller but an identity (one that
  // does not override `caller()`) has its identity passed, as the initial read did before the accessor took a
  // caller.
  std::shared_ptr<const CallerInfo> initialCaller =
    inputs.securityContext ? inputs.securityContext->caller() : nullptr;
  if (!initialCaller && inputs.securityContext)
  {
    if (auto identity = inputs.securityContext->access_identity())
    {
      auto identified = std::make_shared<CallerInfo>();
      identified->identity = std::move(identity);
      initialCaller = std::move(identified);
    }
  }

  // Both started before either is awaited.
  auto euRangeResolution = resolve_eu_ranges(inputs.addressSpace,
    inputs.requestInfo,
    std::move(percentVariables),
    inputs.capabilities.operationLimits.maxNodesPerBrowse);
  // Where the initial values are asked for among the samples held for the items (DL-69 (D7)).
  const uint64_t initialValuesAsked = ++mStrandSequence;
  auto initialValueRead = read_initial_values(inputs.requestInfo, initialCaller, std::move(valueReads));
  auto euRanges = co_await std::move(euRangeResolution);
  auto initialValues = co_await std::move(initialValueRead);
  if (!mCreateRunning)
  {
    co_return;
  }

  for (size_t cursor = 0; cursor < validItems.size(); ++cursor)
  {
    auto& pending = validItems[cursor];
    if (!pending.item)
    {
      continue;
    }

    if (pending.item->isEventItem)
    {
      if (establish_event_item(inputs, results, pending, pending.subject.value()))
      {
        finalise_create_item(pending, results, reservation);
      }
      continue;
    }

    const auto& euRangeIndex = euRangeSlot[cursor];
    if (euRangeIndex)
    {
      // A range that is not usable (high not above low, or a limit not known, which Part 8 5.6.2 gives as
      // NaN) is refused for the same reason: the deadband cannot be computed, and reporting every change
      // without saying so is the same failure.
      const size_t slot = euRangeIndex.value();
      const auto euRange = slot < euRanges.size() ? eu_range_from(euRanges[slot])
                                                  : Result<EuRangeRead>{StatusCode{Status::BadInternalError}};
      if (!euRange.is_good() || !usable_eu_range(euRange.value().low, euRange.value().high))
      {
        results[pending.index].status_code() =
          percent_deadband_refusal(pending.item->itemToMonitor.node_id(), euRange.status_code());
        pending.item.reset();
        continue;
      }
      pending.item->hasEuRange = true;
      pending.item->euRangeLow = euRange.value().low;
      pending.item->euRangeHigh = euRange.value().high;
    }

    if (pending.item->access_denied())
    {
      // Part 4 5.12.2.1: denied items succeed with BadUserAccessDenied on the initial notification (no read).
      // The sampler's real values (the item is registered, for a recheck that allows it later) are dropped
      // rather than overwriting this status - see receive_sample.
      DataValue initialValue;
      initialValue.status() = StatusCode{Status::BadUserAccessDenied};
      initialValue.source_timestamp() = DateTime::now();
      pending.initialValueMark = InitialValueMark{.sourceTimestamp = std::nullopt, .issued = mStrandSequence};
      pending.item->enqueue_initial(std::move(initialValue));
      finalise_create_item(pending, results, reservation);
      continue;
    }

    const auto& initialValueIndex = valueSlot[cursor];
    if (!initialValueIndex)
    {
      // Any other attribute, and a VariableType's Value: from the Node's description (NR-26 step 4c), the
      // source the later samples of these attributes come from too. A failure is the value's status.
      const auto attributeId =
        utils::from_underlying<AttributeId>(pending.item->itemToMonitor.attribute_id());
      DataValue dv;
      auto nodeDescription = ua::detail::NodeAccessorRoute::attributes(pending.subject.value());
      if (nodeDescription.is_good())
      {
        auto described =
          nodeDescription.value().attribute(AccessControl::user_independent_attribute(attributeId));
        dv = described.is_good() ? std::move(described).value() : DataValue{described.status_code()};
      }
      else
      {
        dv = DataValue{nodeDescription.status_code()};
      }
      // The service produced this value, so it narrows it (NR-10 rule 3), except a value the projection
      // produces, which the item narrows after projecting it (DL-69 (D3)).
      if (!AccessControl::produces_value(attributeId))
      {
        index_range_utils::apply_to_value(dv, pending.item->itemToMonitor.index_range());
      }
      stamp_received(dv);
      // Read here, at commit: every sample held for the item reached the strand before it.
      pending.initialValueMark =
        InitialValueMark{.sourceTimestamp = dv.source_timestamp(), .issued = mStrandSequence};
      pending.item->lastUserIndependentValue = dv;
      auto userIndependentValue = dv;
      dv = project_monitored_value(*pending.item, std::move(dv), mAccessControlTimeout, mLogger);
      pending.item->enqueue_initial(std::move(dv), std::move(userIndependentValue));
      finalise_create_item(pending, results, reservation);
      continue;
    }

    const size_t slot = initialValueIndex.value();
    auto readResult = slot < initialValues.size() ? std::move(initialValues[slot])
                                                  : DataValueResult{StatusCode{Status::BadInternalError}};
    if (readResult.has_value())
    {
      // The namespace's code on its answer (a Good subcode or an Uncertain code) and the DataValue's own
      // status share the initial notification's one status.
      const StatusCode answered = readResult.status_code();
      auto value = std::move(readResult).value();
      server::detail::route_outer_status(value,
        answered,
        mLogger,
        "Subscription.InitialValueAnswerCodeNotAnswered",
        pending.item->itemToMonitor.node_id());
      stamp_received(value);
      pending.initialValueMark =
        InitialValueMark{.sourceTimestamp = value.source_timestamp(), .issued = initialValuesAsked};
      pending.item->lastUserIndependentValue = value;
      auto userIndependentValue = value;
      value = project_monitored_value(*pending.item, std::move(value), mAccessControlTimeout, mLogger);
      pending.item->enqueue_initial(std::move(value), std::move(userIndependentValue));
    }
    else
    {
      // A read that failed, or answered Uncertain without a DataValue: its status is the initial value.
      DataValue errorValue;
      errorValue.status() = readResult.status_code();
      errorValue.source_timestamp() = DateTime::now();
      stamp_received(errorValue);
      pending.initialValueMark =
        InitialValueMark{.sourceTimestamp = std::nullopt, .issued = initialValuesAsked};
      pending.item->lastUserIndependentValue = errorValue;
      auto retainedErrorValue = errorValue;
      pending.item->enqueue_initial(std::move(errorValue), std::move(retainedErrorValue));
    }

    finalise_create_item(pending, results, reservation);
  }
}

ua::async::Task<std::vector<DataValueResult>> Subscription::read_initial_values(
  RequestInfo request, std::shared_ptr<const CallerInfo> caller, std::vector<ua::detail::ValueRead> reads)
{
  if (reads.empty())
  {
    co_return std::vector<DataValueResult>{};
  }
  // One call; the route sends one `read_values_async` per namespace, split by maxNodesPerRead (NR-26 step
  // 4b).
  co_return co_await await_step<std::vector<DataValueResult>>(
    [&request, &caller, &reads](auto completion)
    {
      ua::detail::NodeAccessorRoute::read_values(
        request, caller.get(), std::move(reads), 0, true, std::move(completion));
    });
}

bool Subscription::establish_event_item(CreateInputs& inputs, std::vector<MonitoredItemCreateResult>& results,
  PendingItem& pending, const NodeAccessor& node)
{
  // Event items: the SubscribeToEvents check on the Node the create's lookup found, from its description read
  // once (NR-28; no lookup of its own, SVC-10), then a conditional EventBus registration. A Node deleted
  // since its lookup describes itself as not Good, which answers this item alone (DL-69 (E4)).
  const auto nodeDescription = ua::detail::NodeAccessorRoute::attributes(node);
  if (!nodeDescription.is_good())
  {
    results[pending.index].status_code() = nodeDescription.status_code();
    pending.item.reset();
    return false;
  }
  // A NodeClass that defines no EventNotifier (neither Object nor View) has none to test.
  const auto eventNotifier = nodeDescription.value().event_notifier();
  if (!eventNotifier || !eventNotifier->test(EventNotifierType::Bit::SubscribeToEvents))
  {
    std::string summary =
      nodeDescription.value().node_class() == NodeClass::Object
        ? std::string{"Target object does not permit event subscription (SubscribeToEvents not set)"}
        : std::string{"Target view does not permit event subscription (SubscribeToEvents not set)"};
    results[pending.index].status_code() = StatusCode{Status::BadFilterNotAllowed,
      ErrorDetail::build("FilterNotAllowed", std::move(summary), "Subscription")
        .context(ua::ContextKeys::nodeId, to_string(pending.item->itemToMonitor.node_id()))
        .context(ua::ContextKeys::nodeAttribute, to_string(AttributeId::EventNotifier))};
    pending.item.reset();
    return false;
  }

  auto eventBus = inputs.eventBus.lock();
  if (eventBus && !pending.item->access_denied())
  {
    register_event_monitored_item(*pending.item, *eventBus);
  }
  return true;
}

void Subscription::finalise_create_item(
  PendingItem& pending, std::vector<MonitoredItemCreateResult>& results, ServerSlotReservation& reservation)
{
  if (!pending.item)
  {
    return;
  }
  const auto resultIdx = pending.index;
  const auto assignedId = pending.item->id;
  const bool reportable = pending.item->has_reportable_notifications();

  mMonitoredItems[assignedId] = std::move(pending.item);
  pending.committed = true;
  if (reportable)
  {
    ++mReportableItemCount;
  }
  mCreatingItemIds.erase(assignedId);
  if (mSemanticMarksBeforeCommit.erase(assignedId) > 0)
  {
    on_semantics_changed(assignedId);
  }
  if (mStructureMarksBeforeCommit.erase(assignedId) > 0)
  {
    on_structure_changed(assignedId);
  }
  // What the namespace pushed for the item while its create ran: after the initial value it has just queued.
  if (auto held = mHeldBeforeCommit.extract(assignedId))
  {
    deliver_held_before_commit(assignedId, std::move(held.mapped()), pending.initialValueMark);
  }

  // Hand this item's server-wide slot over: the item is now live, so the gauge counts it as a
  // monitored item rather than as a reservation, and the teardown / delete path is what releases it
  // from here on. What the reservation still holds is exactly the items that never committed.
  reservation.hand_one_over();
  account_committed_item(/*reservedInGauge=*/true);

  auto& res = results[resultIdx];
  res.status_code() = pending.answered;
  res.monitored_item_id() = assignedId;
  res.revised_sampling_interval() = pending.revisedSamplingInterval;
  res.revised_queue_size() = pending.revisedQueueSize;

  if (pending.eventFilterResult)
  {
    auto efr = std::make_unique<EventFilterResult>(std::move(*pending.eventFilterResult));
    res.filter_result().inner_unique_ptr() = std::move(efr);
  }
}

void Subscription::deliver_held_before_commit(
  IntegerId monitoredItemId, HeldBeforeCommit held, const std::optional<InitialValueMark>& initialValueMark)
{
  auto* item = find_monitored_item(monitoredItemId);
  if (!item)
  {
    return;
  }
  // Only what is newer than the initial value: a sample the initial read already overtook would make the
  // client's next notification older than its first (DL-69 (D7)).
  for (auto& sample : held.samples)
  {
    if (initialValueMark &&
        !newer_than_initial(
          sample.value, sample.arrival, initialValueMark->sourceTimestamp, initialValueMark->issued))
    {
      continue;
    }
    receive_sample(monitoredItemId, *item, std::move(sample.value));
  }
  if (held.notice)
  {
    on_sample_invalidated(monitoredItemId, *held.notice);
  }
}

Subscription::CreateMonitoredItemsCallback Subscription::take_create_completion()
{
  // Whoever gets here first ends the create and answers it once. @see take_delete_completion
  auto callback = std::move(mCreateCompletion);
  mCreateCompletion = nullptr;
  mCreateRunning = false;
  mCreateItemCount = 0;
  mCreatingItemIds.clear();
  mSemanticMarksBeforeCommit.clear();
  mStructureMarksBeforeCommit.clear();
  mHeldBeforeCommit.clear();
  // A namespace still working for the create may stop: nothing it answers from here on is read.
  if (auto cancelled = std::exchange(mCreateCancelled, nullptr))
  {
    cancelled->store(true, std::memory_order_release);
  }

  // What the slot pins is the root task's inputs - the client's whole request, the caller's
  // AddressSpace handle, its session security context and its two configuration snapshots - and
  // nothing would release them until the NEXT create overwrote the slot.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation = mCreateGeneration](Subscription& self)
    {
      if (self.mCreateGeneration == generation && !self.mCreateRunning)
      {
        self.mCreateTask = {};
      }
    })();

  return callback;
}

void Subscription::finish_create(
  std::vector<MonitoredItemCreateResult> results, ServerSlotReservation& reservation)
{
  // Release the reservation BEFORE the answer, so an observer that reads the server-wide gauge when
  // the answer arrives sees a consistent count. What is left in it is exactly the items that failed
  // downstream - authorization, namespace registration, the initial value read. Doing it here rather
  // than leaving it to the reservation's destructor is what puts it on the right side of the answer;
  // the destructor is the safety net for the paths that never reach here.
  reservation.release_now();

  auto cb = take_create_completion();

  if (mReportableItemCount > 0)
  {
    mHasNotifications.store(true, std::memory_order_release);
  }
  update_info();

  if (cb)
  {
    cb(std::move(results));
  }
}

void Subscription::fail_create(StatusCode status)
{
  // Ends the create with one status for every row it was given.
  //
  // Two limits, both of them inherited and both of them better than what they replace. FIRST, the
  // rows: this answers Bad for all of them, including any that had already committed before a step
  // threw, so the client is told nothing was created while those items are live inside the
  // subscription and it has no ids for them. The chain this replaces never answered that client at
  // all - the throw was swallowed and the gate latched for the subscription's life - so the items
  // were equally unreachable and the client waited for ever. Answering truthfully needs a per-row
  // record of what has been answered, which is its own change. SECOND, the slots: on the throw path
  // the body unwinds first, so its reservation is released BEFORE this answers; on the
  // ~Subscription path the body is still suspended and its frame is destroyed with the task member,
  // just after. Nothing observes the gauge in between, and `close()` has already reconciled what the
  // subscription itself held.
  if (!mCreateRunning)
  {
    return;
  }
  const size_t requestSize = mCreateItemCount;
  auto cb = take_create_completion();

  std::vector<MonitoredItemCreateResult> failed(requestSize);
  for (auto& r : failed)
  {
    r.status_code() = status;
  }
  if (cb)
  {
    cb(std::move(failed));
  }
}

void Subscription::register_event_monitored_item(MonitoredItem& item, EventBus& eventBus)
{
  // Subscribe an event MonitoredItem to the EventBus and record the handle on the item. Shared by the
  // create Phase-3 registration and the deny->allow access-recheck transition (an item whose
  // ReceiveEvents permission was regained must resume receiving events - Part 4 5.12.2.1). The
  // delivery callback weak-captures the subscription and posts to its strand; the inner lambda
  // re-resolves the item by id (it may have been deleted between dispatch and the strand turn).
  auto monitoredNode = item.itemToMonitor.node_id();
  auto monitoredItemId = item.id;
  mRegisteredEventBus = eventBus.weak_from_this();

  // The EventBus stores this callback and invokes it ONCE PER EVENT (multi-shot), so it uses
  // post_borrowing_repeating - NOT the single-shot post_borrowing/post_owning, which move their
  // handler into the posted work on the first delivery and silently no-op on every event after.
  // The handler runs on the subscription strand with a live Subscription& and re-resolves the item
  // by id (it may have been deleted between dispatch and the strand turn).
  item.eventBusHandle = eventBus.register_event_item(monitoredNode,
    monitoredItemId,
    mId,
    ua::async::post_borrowing_repeating(this,
      mStrand,
      mLogger,
      [monitoredItemId](Subscription& self,
        IntegerId /*deliveredMiId*/,
        std::shared_ptr<const BaseEvent>
          event,
        std::shared_ptr<const event_type_model::DeclarationsResult>
          declarationModel)
      { self.enqueue_event_delivery(monitoredItemId, std::move(event), std::move(declarationModel)); }),
    true);
}

void Subscription::enqueue_event_delivery(IntegerId monitoredItemId, std::shared_ptr<const BaseEvent> event,
  std::shared_ptr<const event_type_model::DeclarationsResult> declarationModel)
{
  if (mClosed || !event)
    return;
  auto* item = find_monitored_item(monitoredItemId);
  if (!item || !item->isEventItem || item->monitoringMode == MonitoringMode::Disabled)
    return;
  // SVC-5 (SVR-MI-GEN-020..023): the hand-off FIFO holds at most queueSize events per item, decided
  // with the item's own discard policy and accounted exactly as a delivered-queue overflow is. The
  // active head is never dropped: its authorization is in flight. Cost: one hash lookup per event;
  // under discard-newest the overflow event's place is the last accepted ordinal (O(1)); under
  // discard-oldest the scan for the oldest droppable entry runs only on overflow, over a FIFO that is
  // bounded by this rule.
  // The ConditionRefresh events (RefreshStart/RefreshEnd/RefreshRequired, Part 9 5.5.7) are never
  // dropped: they frame or announce a refresh the client is waiting for. They are counted like any
  // other event so the bound stays exact for the events that can be dropped.
  const auto& eventType = event->eventType;
  const bool refreshEvent = eventType == NodeId{ObjectTypeId::RefreshStartEventType} ||
                            eventType == NodeId{ObjectTypeId::RefreshEndEventType} ||
                            eventType == NodeId{ObjectTypeId::RefreshRequiredEventType};
  auto& accounting = mPendingEventAccounting[monitoredItemId];
  if (!refreshEvent && accounting.count >= item->queueSize)
  {
    const bool firstLossOfEpisode = !item->overflowEventPending;
    item->note_event_queue_overflow();
    if (!item->discardOldest)
    {
      // COND-920: a Condition event lost before authorization needs a RefreshRequired like one lost
      // from the delivered queue.
      if (event->is_condition_event())
        item->refreshRequired = true;
      // The overflow event belongs after the newest event kept at the FIRST loss of the episode
      // (SVR-EVT-MON-008): a later loss in the same episode must not move it, or a storm that outpaces
      // authorization would postpone the announcement for as long as it lasts. Under discard-newest the
      // newest kept entry is simply the last one accepted.
      if (firstLossOfEpisode)
        item->overflowEventAfterOrdinal = accounting.lastAcceptedOrdinal;
      return;
    }
    const auto isRefresh = [](const PendingEventDelivery& pending)
    {
      if (!pending.event)
        return false;
      const auto& type = pending.event->eventType;
      return type == NodeId{ObjectTypeId::RefreshStartEventType} ||
             type == NodeId{ObjectTypeId::RefreshEndEventType} ||
             type == NodeId{ObjectTypeId::RefreshRequiredEventType};
    };
    // The victim is the oldest droppable entry: never the active head, never a refresh event. The head
    // is kept even when it is older than the events dropped in its place: discarding it would let a
    // storm that outpaces authorization stop delivery altogether, since every arrival would discard the
    // next head too. Part 4 7.21 discards the oldest Notification, and these are not Notifications yet;
    // the delivered queue discards its oldest as the clause requires. The loss is announced by the
    // overflow event (D-SVR-MI-GEN-020-EVENT-IN-AUTHORIZATION-SURVIVES-DISCARD-OLDEST, waived).
    const auto oldest = std::find_if(mPendingEventDeliveries.begin(),
      mPendingEventDeliveries.end(),
      [&](const PendingEventDelivery& pending)
      {
        return pending.monitoredItemId == monitoredItemId &&
               !(mEventDeliveryActive && pending.ordinal == mActiveEventDeliveryOrdinal) &&
               !isRefresh(pending);
      });
    if (oldest == mPendingEventDeliveries.end())
    {
      if (event->is_condition_event())
        item->refreshRequired = true;
      return;  // nothing droppable is pending: the newcomer is the one that has to go
    }
    if (oldest->event && oldest->event->is_condition_event())
      item->refreshRequired = true;
    mPendingEventDeliveries.erase(oldest);
    --accounting.count;
  }
  ++accounting.count;
  const uint64_t ordinal = mNextEventDeliveryOrdinal++;
  accounting.lastAcceptedOrdinal = ordinal;
  mPendingEventDeliveries.push_back(
    PendingEventDelivery{ordinal, monitoredItemId, std::move(event), std::move(declarationModel)});
  if (!mEventDeliveryActive)
    start_next_event_delivery();
}

void Subscription::discard_pending_event_deliveries(IntegerId monitoredItemId)
{
  const bool discardsActive = mEventDeliveryActive && !mPendingEventDeliveries.empty() &&
                              mPendingEventDeliveries.front().monitoredItemId == monitoredItemId;
  std::erase_if(mPendingEventDeliveries,
    [monitoredItemId](const PendingEventDelivery& pending)
    { return pending.monitoredItemId == monitoredItemId; });
  mPendingEventAccounting.erase(monitoredItemId);
  if (!discardsActive)
    return;

  mEventDeliveryDeadlineTimer.cancel();
  ++mEventDeliveryAttemptEpoch;
  mEventDeliveryAccessControl.reset();
  mEventDeliveryPlan.clear();
  mEventDeliveryResolvedItems.clear();
  mEventDeliveryResolvedPlanIndices.clear();
  mEventDeliveryVerdicts.clear();
  mActiveEventDeliveryOrdinal = 0;
  mEventDeliveryActive = false;
  if (!mPendingEventDeliveries.empty() && !mClosed)
    start_next_event_delivery();
}

void Subscription::start_next_event_delivery()
{
  mEventDeliveryDeadlineTimer.cancel();
  mEventDeliveryAccessControl.reset();
  mEventDeliveryPlan.clear();
  mEventDeliveryResolvedItems.clear();
  mEventDeliveryResolvedPlanIndices.clear();
  mEventDeliveryVerdicts.clear();

  if (mClosed || mPendingEventDeliveries.empty())
  {
    mEventDeliveryActive = false;
    mActiveEventDeliveryOrdinal = 0;
    return;
  }
  mEventDeliveryActive = true;
  mActiveEventDeliveryOrdinal = mPendingEventDeliveries.front().ordinal;
  const uint64_t ordinal = mActiveEventDeliveryOrdinal;
  mEventDeliveryDeadline = std::chrono::steady_clock::now() + mAccessControlTimeout;
  mEventDeliveryDeadlineTimer = Timer::schedule_after(mStrand,
    mAccessControlTimeout,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [ordinal](Subscription& self, boost::system::error_code error)
      {
        if (!error)
          self.on_event_delivery_deadline(ordinal);
      }));
  start_event_delivery_attempt(ordinal);
}

void Subscription::start_event_delivery_attempt(uint64_t ordinal)
{
  if (!mEventDeliveryActive || mActiveEventDeliveryOrdinal != ordinal || mPendingEventDeliveries.empty() ||
      mPendingEventDeliveries.front().ordinal != ordinal)
  {
    return;
  }

  const auto now = std::chrono::steady_clock::now();
  if (now >= mEventDeliveryDeadline)
  {
    on_event_delivery_deadline(ordinal);
    return;
  }

  mEventDeliveryAccessControl.reset();
  mEventDeliveryPlan.clear();
  mEventDeliveryResolvedItems.clear();
  mEventDeliveryResolvedPlanIndices.clear();
  mEventDeliveryVerdicts.clear();
  ++mEventDeliveryAttemptEpoch;
  const uint64_t attemptEpoch = mEventDeliveryAttemptEpoch;

  const auto& pending = mPendingEventDeliveries.front();
  auto* item = find_monitored_item(pending.monitoredItemId);
  auto securityContext = mRecheckSecurityContext.lock();
  auto addressSpace = mRecheckAddressSpace.lock();
  if (!item || !item->isEventItem || item->access_denied() || !item->eventFilter || !securityContext ||
      !addressSpace)
  {
    complete_event_delivery(ordinal, false, event_delivery_state_unavailable(ordinal));
    return;
  }

  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(mEventDeliveryDeadline - now);
  mEventDeliveryAccessControl =
    SessionAccessControl::create(*securityContext, *addressSpace, remaining, mLogger);
  if (!mEventDeliveryAccessControl)
  {
    complete_event_delivery(ordinal, false, event_delivery_state_unavailable(ordinal));
    return;
  }
  mEventDeliveryIdentity = mEventDeliveryAccessControl->identity()->key();

  mEventDeliveryPlan.push_back(CompiledEventFilter::AuthorizationSubject{
    receive_events_source_subject(pending.event->sourceNode), AccessOperation::ReceiveEvents});
  mEventDeliveryPlan.push_back(
    CompiledEventFilter::AuthorizationSubject{pending.event->eventType, AccessOperation::ReceiveEvents});
  auto filterSubjects = item->eventFilter->authorization_subjects(*pending.event, pending.declarationModel);
  mEventDeliveryPlan.insert(mEventDeliveryPlan.end(),
    std::make_move_iterator(filterSubjects.begin()),
    std::make_move_iterator(filterSubjects.end()));

  std::vector<NodeId> subjectIds;
  subjectIds.reserve(mEventDeliveryPlan.size());
  for (const auto& subject : mEventDeliveryPlan)
    subjectIds.push_back(subject.nodeId);
  addressSpace->find_nodes_async(subjectIds,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [ordinal, attemptEpoch](Subscription& self, BatchResult<NodeAccessorResult> batch)
      { self.on_event_subjects_resolved(ordinal, attemptEpoch, std::move(batch)); }));
}

void Subscription::on_event_subjects_resolved(
  uint64_t ordinal, uint64_t attemptEpoch, BatchResult<NodeAccessorResult> batch)
{
  if (!event_delivery_attempt_matches(ordinal, attemptEpoch))
    return;
  if (std::chrono::steady_clock::now() >= mEventDeliveryDeadline)
  {
    on_event_delivery_deadline(ordinal);
    return;
  }
  if (!event_delivery_identity_is_current())
  {
    start_event_delivery_attempt(ordinal);
    return;
  }
  if (!mEventDeliveryAccessControl || batch.batchStatus.is_bad() ||
      batch.items.size() != mEventDeliveryPlan.size())
  {
    const StatusCode cause = batch.batchStatus.is_bad() ? batch.batchStatus.status_code()
                                                        : event_delivery_state_unavailable(ordinal);
    complete_event_delivery(ordinal, false, cause);
    return;
  }

  mEventDeliveryVerdicts.resize(mEventDeliveryPlan.size());
  mEventDeliveryResolvedItems.reserve(mEventDeliveryPlan.size());
  mEventDeliveryResolvedPlanIndices.reserve(mEventDeliveryPlan.size());
  for (size_t index = 0; index < batch.items.size(); ++index)
  {
    const auto& subject = mEventDeliveryPlan[index];
    auto& result = batch.items[index];
    // An answer that is not Good holds no Node to authorize: an Uncertain one denies as a Bad one does
    // (DL-45).
    if (!result.is_good())
    {
      const auto deniedCause = event_subject_resolution_denied(subject, result.status_code());
      mEventDeliveryVerdicts[index] = AccessControl::Verdict{
        .subject = subject.nodeId, .operation = subject.operation, .permitted = false, .cause = deniedCause};
      if (index < 2)
      {
        complete_event_delivery(ordinal, false, deniedCause);
        return;
      }
      continue;
    }
    mEventDeliveryResolvedPlanIndices.push_back(index);
    mEventDeliveryResolvedItems.push_back(AccessControl::Item{std::move(result).value(), subject.operation});
  }

  mEventDeliveryAccessControl->authorize_async(RequestInfo{},
    mEventDeliveryResolvedItems,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [ordinal, attemptEpoch](Subscription& self, std::vector<AccessControl::Verdict> verdicts)
      { self.on_event_subjects_authorized(ordinal, attemptEpoch, std::move(verdicts)); }));
}

void Subscription::on_event_subjects_authorized(
  uint64_t ordinal, uint64_t attemptEpoch, std::vector<AccessControl::Verdict> verdicts)
{
  if (!event_delivery_attempt_matches(ordinal, attemptEpoch))
    return;
  if (std::chrono::steady_clock::now() >= mEventDeliveryDeadline)
  {
    on_event_delivery_deadline(ordinal);
    return;
  }
  if (!event_delivery_identity_is_current())
  {
    start_event_delivery_attempt(ordinal);
    return;
  }
  if (verdicts.size() != mEventDeliveryResolvedPlanIndices.size())
  {
    complete_event_delivery(ordinal, false, event_delivery_state_unavailable(ordinal));
    return;
  }

  for (size_t index = 0; index < verdicts.size(); ++index)
    mEventDeliveryVerdicts[mEventDeliveryResolvedPlanIndices[index]] = std::move(verdicts[index]);
  if (mEventDeliveryVerdicts.size() < 2 || !mEventDeliveryVerdicts[0].permitted ||
      !mEventDeliveryVerdicts[1].permitted)
  {
    StatusCode cause = event_delivery_state_unavailable(ordinal);
    if (!mEventDeliveryVerdicts.empty() && mEventDeliveryVerdicts[0].cause.is_bad())
      cause = mEventDeliveryVerdicts[0].cause;
    else if (mEventDeliveryVerdicts.size() > 1 && mEventDeliveryVerdicts[1].cause.is_bad())
      cause = mEventDeliveryVerdicts[1].cause;
    complete_event_delivery(ordinal, false, cause);
    return;
  }
  complete_event_delivery(ordinal, true, StatusCode{Status::Good});
}

void Subscription::on_event_delivery_deadline(uint64_t ordinal)
{
  if (!mEventDeliveryActive || mActiveEventDeliveryOrdinal != ordinal)
    return;
  ++mEventDeliveryAttemptEpoch;
  complete_event_delivery(ordinal, false, event_delivery_deadline_exceeded(ordinal));
}

void Subscription::restart_active_event_delivery_for_identity_change()
{
  if (!mEventDeliveryActive || mPendingEventDeliveries.empty())
    return;
  if (!event_delivery_identity_is_current())
    start_event_delivery_attempt(mActiveEventDeliveryOrdinal);
}

bool Subscription::event_delivery_attempt_matches(uint64_t ordinal, uint64_t attemptEpoch) const noexcept
{
  return mEventDeliveryActive && mActiveEventDeliveryOrdinal == ordinal &&
         mEventDeliveryAttemptEpoch == attemptEpoch && !mPendingEventDeliveries.empty() &&
         mPendingEventDeliveries.front().ordinal == ordinal;
}

bool Subscription::event_delivery_identity_is_current() const
{
  auto securityContext = mRecheckSecurityContext.lock();
  if (!securityContext)
    return false;
  const auto identity = securityContext->access_identity();
  return identity && identity->key() == mEventDeliveryIdentity;
}

void Subscription::log_event_delivery_failure(const StatusCode& status) const
{
  if (!status.is_bad())
    return;
  // A Role or AccessRestrictions decision is the authorization working: the session may not receive this
  // Event or field, and that happens for every such Event on every such Subscription. Only a failure to reach
  // a decision - the deadline, lost delivery state, a namespace that could not answer - withholds an Event
  // the session may be entitled to, and that is what an operator needs to see. The status code cannot tell
  // them apart: a namespace that could not answer is also reported as Bad_UserAccessDenied
  // (AuthorizationResolutionFailed), so that the wire fails closed. The detail code can.
  const auto detail = status.shared_detail();
  const bool denied =
    detail && (detail->code == "RoleNotGranted" || detail->code == "RoleUnknownToConfiguration" ||
                detail->code == "AccessRestrictionsNotSatisfied");
  if (denied)
  {
    if (!mLogger.is_enabled(LogLevel::Debug))
      return;  // the fields below are formatted eagerly; a routine denial must cost nothing when not logged
    mLogger.debug(
      {{"status", to_string(status)}, {"detail", to_string(*detail)}}, "Event withheld by access control");
    return;
  }
  if (detail)
  {
    mLogger.warning({{"status", to_string(status)}, {"detail", to_string(*detail)}},
      "Event delivery authorization failed closed");
  }
  else
  {
    mLogger.warning({{"status", to_string(status)}}, "Event delivery authorization failed closed");
  }
}

void Subscription::complete_event_delivery(uint64_t ordinal, bool deliver, StatusCode terminalCause)
{
  if (!mEventDeliveryActive || mActiveEventDeliveryOrdinal != ordinal || mPendingEventDeliveries.empty() ||
      mPendingEventDeliveries.front().ordinal != ordinal)
  {
    return;
  }
  if (deliver && std::chrono::steady_clock::now() >= mEventDeliveryDeadline)
  {
    ++mEventDeliveryAttemptEpoch;
    deliver = false;
    terminalCause = event_delivery_deadline_exceeded(ordinal);
  }
  if (deliver && (!mEventDeliveryAccessControl || !event_delivery_identity_is_current()))
  {
    if (mEventDeliveryAccessControl && !event_delivery_identity_is_current())
    {
      start_event_delivery_attempt(ordinal);
      return;
    }
    deliver = false;
    terminalCause = event_delivery_state_unavailable(ordinal);
  }

  bool notifyReady = false;
  if (deliver)
  {
    try
    {
      const auto& pending = mPendingEventDeliveries.front();
      auto* item = find_monitored_item(pending.monitoredItemId);
      if (!item || !item->isEventItem || item->access_denied() || !item->eventFilter || !pending.event)
      {
        deliver = false;
        terminalCause = event_delivery_state_unavailable(ordinal);
      }
      else
      {
        for (const auto& verdict : mEventDeliveryVerdicts)
        {
          if (!verdict.permitted && verdict.cause.shared_detail())
            log_event_delivery_failure(verdict.cause);
        }
        if (item->eventFilter->evaluate_authorized(
              *pending.event, pending.declarationModel, mEventDeliveryVerdicts))
        {
          auto fieldList = item->eventFilter->project_authorized(*pending.event,
            item->clientHandle,
            pending.declarationModel,
            *mEventDeliveryAccessControl,
            mEventDeliveryResolvedItems,
            mEventDeliveryVerdicts,
            mMaxResponseMessageSize);
          const bool hadNotifications = item->has_reportable_notifications();
          item->enqueue_event(std::move(fieldList),
            pending.event->is_condition_event(),
            RetainedEventProjection{item->clientHandle,
              pending.event->sourceNode,
              pending.event->eventType,
              pending.event,
              retained_declaration_model(pending.declarationModel),
              item->eventFilter->retained_copy()});
          if (!hadNotifications && item->has_reportable_notifications())
            ++mReportableItemCount;
          update_info();
          if (item->has_reportable_notifications())
          {
            mHasNotifications.store(true, std::memory_order_release);
            notifyReady = mPublishReqQueued.load(std::memory_order_acquire) && static_cast<bool>(mOnReady);
          }
        }
      }
    }
    catch (...)
    {
      deliver = false;
      terminalCause = ua::exception_to_status_code(std::current_exception());
    }
  }

  if (!deliver && terminalCause.is_bad())
    log_event_delivery_failure(terminalCause);

  {
    // Discard-newest (SVC-5): the overflow event announcing a pre-authorization loss is queued once the
    // newest event kept at that loss has left the FIFO - delivered or not - so it sits where the missing
    // events would have been (SVR-EVT-MON-008), with the delivered path's reportable bookkeeping.
    const auto& head = mPendingEventDeliveries.front();
    if (auto* item = find_monitored_item(head.monitoredItemId);
        item && item->overflowEventPending && !item->discardOldest &&
        head.ordinal >= item->overflowEventAfterOrdinal && item->monitoringMode != MonitoringMode::Disabled)
    {
      const bool hadNotifications = item->has_reportable_notifications();
      item->insert_overflow_event_once();
      if (!hadNotifications && item->has_reportable_notifications())
        ++mReportableItemCount;
      update_info();
      if (item->has_reportable_notifications())
      {
        mHasNotifications.store(true, std::memory_order_release);
        notifyReady = mPublishReqQueued.load(std::memory_order_acquire) && static_cast<bool>(mOnReady);
      }
    }
  }
  if (const auto accounting = mPendingEventAccounting.find(mPendingEventDeliveries.front().monitoredItemId);
      accounting != mPendingEventAccounting.end() && --accounting->second.count == 0)
  {
    mPendingEventAccounting.erase(accounting);
  }
  mPendingEventDeliveries.pop_front();
  mEventDeliveryDeadlineTimer.cancel();
  ++mEventDeliveryAttemptEpoch;
  mEventDeliveryAccessControl.reset();
  mEventDeliveryPlan.clear();
  mEventDeliveryResolvedItems.clear();
  mEventDeliveryResolvedPlanIndices.clear();
  mEventDeliveryVerdicts.clear();
  mActiveEventDeliveryOrdinal = 0;
  mEventDeliveryActive = false;
  if (!mPendingEventDeliveries.empty() && !mClosed)
  {
    ua::async::post_borrowing(
      this, mStrand, mLogger, [](Subscription& self) { self.start_next_event_delivery(); })();
  }
  if (notifyReady && mOnReady)
    mOnReady(mId);
}

// --- DeleteMonitoredItems ---

/// One delete, in the order the handler chain walked it.
void Subscription::start_delete(std::vector<IntegerId> monitoredItemIds, AddressSpace addressSpace,
  std::weak_ptr<EventBus> eventBus, std::shared_ptr<ServerSummaryCounters> summaryCounters)
{
  // A task is EAGER: the body runs to its first suspension before this returns, and a delete with no
  // monitoring handles to release - an empty list, only event items, only ids that miss the lookup -
  // finishes there and then, firing its answer, which may start the NEXT delete before this one has
  // been stored. Storing ours unconditionally would then overwrite a running frame with a finished
  // one. The generation says whether the slot is still ours to fill.
  const uint64_t generation = ++mDeleteGeneration;
  auto deletion = run_delete(
    std::move(monitoredItemIds), std::move(addressSpace), std::move(eventBus), std::move(summaryCounters));
  if (mDeleteGeneration == generation)
  {
    mDeleteTask = std::move(deletion);
  }
}

ua::async::Task<> Subscription::run_delete(std::vector<IntegerId> monitoredItemIds, AddressSpace addressSpace,
  std::weak_ptr<EventBus> eventBus, std::shared_ptr<ServerSummaryCounters> summaryCounters)
{
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise
  // nobody reads. That leaves the client's DeleteMonitoredItems unanswered AND latches
  // `mDeleteRunning`, which refuses every later delete on this subscription and stops it ever
  // re-authorizing its items: the periodic recheck silently skips its cycle and a MANDATORY one -
  // the one an identity change needs - is refused BadServerTooBusy, for the subscription's life.
  try
  {
    co_await walk_delete(monitoredItemIds, addressSpace, eventBus, summaryCounters);
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the delete and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mDeleteRunning)
        {
          fail_delete(ua::exception_to_status_code(std::current_exception()));
        }
      })();
  }
  co_return;
}

ua::async::Task<> Subscription::walk_delete(const std::vector<IntegerId>& monitoredItemIds,
  AddressSpace& addressSpace, const std::weak_ptr<EventBus>& eventBus,
  const std::shared_ptr<ServerSummaryCounters>& summaryCounters)
{
  // Everything up to the first namespace call is this subscription's own bookkeeping, and runs in
  // one turn: each named item is looked up, an event item is deregistered from the EventBus and a
  // variable item's monitoring handle is collected against the namespace that issued it, and the
  // item is removed from this subscription's own state, so no sample reaches it from here on.
  std::vector<StatusCode> results(monitoredItemIds.size());
  std::map<uint16_t, std::vector<std::pair<size_t, MonitoringHandle>>> released;
  uint32_t removedCount = 0;

  for (size_t i = 0; i < monitoredItemIds.size(); ++i)
  {
    auto it = mMonitoredItems.find(monitoredItemIds[i]);
    if (it == mMonitoredItems.end())
    {
      results[i] = StatusCode{Status::BadMonitoredItemIdInvalid};
      continue;
    }

    auto& item = *it->second;

    if (item.isEventItem && item.eventBusHandle != 0)
    {
      if (auto bus = eventBus.lock())
      {
        bus->deregister_event_item(item.eventBusHandle);
      }
    }
    else if (item.namespaceHandle != 0)
    {
      released[item.namespaceIndex].emplace_back(i, item.namespaceHandle);
    }

    if (item.has_reportable_notifications() && mReportableItemCount > 0)
    {
      --mReportableItemCount;
    }

    mTriggerLinks.erase(monitoredItemIds[i]);
    for (auto& [triggering, triggered] : mTriggerLinks)
    {
      triggered.erase(monitoredItemIds[i]);
    }

    mMonitoredItems.erase(it);
    ++removedCount;
    results[i] = StatusCode{Status::Good};
  }

  // Then every namespace that issued a handle is asked at once to release it, and the delete answers when
  // each has answered: an item's result is its namespace's answer for its handle, a Good subcode, an
  // Uncertain or a Bad code included. The items are gone from here whatever the namespaces answer.
  std::vector<ua::async::Task<>> units;
  units.reserve(released.size());
  for (const auto& [namespaceIndex, nsItems] : released)
  {
    units.push_back(delete_in_namespace(addressSpace, namespaceIndex, nsItems, results));
  }
  for (auto& unit : units)
  {
    co_await std::move(unit);
  }

  if (mDeleteRunning)
  {
    finish_delete(std::move(results), removedCount, summaryCounters);
  }
  co_return;
}

ua::async::Task<> Subscription::delete_in_namespace(AddressSpace& addressSpace, uint16_t namespaceIndex,
  const std::vector<std::pair<size_t, MonitoringHandle>>& nsItems, std::vector<StatusCode>& results)
{
  auto ns = addressSpace.namespace_array().get_namespace(namespaceIndex);
  if (!ns)
  {
    // The namespace is no longer registered: it holds nothing to release, and the items are deleted.
    co_return;
  }
  // The namespace views the handles until it answers, so they live in the answer's capture: a release
  // outlives this request, and outlives this Subscription when it is destroyed before the namespace answers.
  auto handles = std::make_shared<std::vector<MonitoringHandle>>();
  handles->reserve(nsItems.size());
  for (const auto& nsItem : nsItems)
  {
    handles->push_back(nsItem.second);
  }

  // The entry guards the call (NR-45 rule 3): its answer is a Bad batch status or one result per handle, and
  // it answers once, a throw included. The release is the server's own, since it outlives its request.
  auto batch = co_await await_step<BatchResult<VoidResult>>(
    [&ns, handles](auto completion)
    {
      ua::detail::MonitoringEntry::remove(ns,
        RequestInfo{},
        *handles,
        [handles, completion = std::move(completion)](BatchResult<VoidResult> answer) mutable
        { completion(std::move(answer)); });
    });

  if (!mDeleteRunning)
  {
    // Something else ended this delete and answered its caller.
    co_return;
  }

  size_t failed = 0;
  for (size_t j = 0; j < nsItems.size(); ++j)
  {
    StatusCode answer =
      batch.batchStatus.is_bad()
        ? batch.batchStatus.status_code()
        : (j < batch.items.size() ? batch.items[j].status_code() : StatusCode{Status::BadInternalError});
    if (answer.is_bad())
    {
      ++failed;
    }
    results[nsItems[j].first] = std::move(answer);
  }
  if (failed > 0)
  {
    mLogger.with_category("subscription")
      .warning({{"namespace_index", std::to_string(namespaceIndex)},
                 {"failed", std::to_string(failed)},
                 {"status", to_string(batch.batchStatus.status_code())}},
        "A namespace did not release monitoring handles the server no longer uses");
  }
  co_return;
}

Subscription::DeleteMonitoredItemsCallback Subscription::take_delete_completion()
{
  // Whoever gets here first ends the delete and answers it once - the body on its way out, or
  // ~Subscription answering for a body that can no longer be asked. Clearing the flag is what an
  // in-flight body reads to discover it was one of the ones that did not get there first.
  auto onComplete = std::move(mDeleteCompletion);
  mDeleteCompletion = nullptr;
  mDeleteRunning = false;
  mDeleteItemCount = 0;

  // What the slot pins is the ROOT task's parameters - the caller's strong AddressSpace handle, its
  // summary counters and the list of ids - and nothing would release them until the NEXT delete
  // overwrote the slot, which for most subscriptions is never. The handles collected per namespace
  // are not among them: they are locals of the nested body, and a local goes when the body ends.
  // Released on a later turn, because this is reached from inside that very frame, and guarded by
  // the generation because the answer may start the next delete before that turn runs.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation = mDeleteGeneration](Subscription& self)
    {
      if (self.mDeleteGeneration == generation && !self.mDeleteRunning)
      {
        self.mDeleteTask = {};
      }
    })();

  return onComplete;
}

void Subscription::finish_delete(std::vector<StatusCode> results, uint32_t removedCount,
  const std::shared_ptr<ServerSummaryCounters>& summaryCounters)
{
  // The count is decremented AFTER the namespace calls and BEFORE the answer, so an observer that
  // reads it when the answer arrives sees a consistent post-delete state. It counts the items removed
  // from this subscription, whatever their namespaces answered.
  auto cb = take_delete_completion();

  if (removedCount > 0)
  {
    account_deleted_items(removedCount, summaryCounters);
  }

  mHasNotifications.store(notifications_available(), std::memory_order_release);
  update_info();

  if (cb)
  {
    cb(std::move(results));
  }
}

void Subscription::fail_delete(StatusCode status)
{
  // Ends the delete with one status for every id it was given. Read the count before ending the
  // delete, because ending it is what releases the count along with everything else.
  if (!mDeleteRunning)
  {
    return;
  }
  const size_t itemCount = mDeleteItemCount;
  auto cb = take_delete_completion();

  std::vector<StatusCode> failed(itemCount, status);
  if (cb)
  {
    cb(std::move(failed));
  }
}

// --- ModifyMonitoredItems ---

/// One modify, in the order the handler chain walked it.
void Subscription::start_modify(ModifyMonitoredItemsRequest request, AddressSpace addressSpace,
  ServerConfig::ServerCapabilities capabilities, ServerConfig::SubscriptionLimits subscriptionLimits,
  RequestInfo requestInfo)
{
  // A task is EAGER, and a modify with no namespace handles to tell finishes without ever
  // suspending, firing its answer before this returns. @see start_delete
  const uint64_t generation = ++mModifyGeneration;
  auto modification = run_modify(std::move(request),
    std::move(addressSpace),
    std::move(capabilities),
    std::move(subscriptionLimits),
    std::move(requestInfo));
  if (mModifyGeneration == generation)
  {
    mModifyTask = std::move(modification);
  }
}

ua::async::Task<> Subscription::run_modify(ModifyMonitoredItemsRequest request, AddressSpace addressSpace,
  ServerConfig::ServerCapabilities capabilities, ServerConfig::SubscriptionLimits subscriptionLimits,
  RequestInfo requestInfo)
{
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise
  // nobody reads, leaving the client's ModifyMonitoredItems unanswered and `mModifyRunning` latched
  // against every later modify and both access rechecks.
  try
  {
    co_await walk_modify(request, addressSpace, capabilities, subscriptionLimits, requestInfo);
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the modify and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mModifyRunning)
        {
          fail_modify(ua::exception_to_status_code(std::current_exception()));
        }
      })();
  }
  co_return;
}

ua::async::Task<> Subscription::walk_modify(const ModifyMonitoredItemsRequest& request,
  AddressSpace& addressSpace, const ServerConfig::ServerCapabilities& capabilities,
  const ServerConfig::SubscriptionLimits& subscriptionLimits, const RequestInfo& requestInfo)
{
  // Everything that can be decided without asking a namespace is decided in one turn: each request row is
  // validated and revised. The rows asking for an AbsoluteDeadband, and the PercentDeadband rows whose item
  // holds no usable range, then need their Variable: those are looked up in one call per namespace, and their
  // DataTypes decided and EURanges read together. Each row's item is then looked up again, because a delete
  // may have removed it meanwhile; an item that keeps its monitoring locally is changed there and then, and
  // one a namespace issued a handle for is collected against that namespace. The successful rows are filled
  // in at the end, once every namespace has answered.
  const auto& itemsToModify = request.items_to_modify();
  std::vector<MonitoredItemModifyResult> results(itemsToModify.size());

  const Duration publishInterval = mPublishingInterval;
  const Duration minSampling = capabilities.minSupportedSampleRate;
  const Duration maxSampling = 60000;
  // Durable subscriptions lift the queue ceiling so clients can buffer large value runs offline
  // (Part 4 5.13.9). Non-durable subscriptions use the configured/default cap.
  const uint32_t configuredMaxQueueSize = capabilities.maxMonitoredItemsQueueSize.value_or(1000);
  const uint32_t maxQueueSize =
    mDurable ? std::max(configuredMaxQueueSize, subscriptionLimits.maxDurableMonitoredItemQueueSize)
             : configuredMaxQueueSize;

  // One validated row, and what it still needs before it can be staged.
  struct ModifyRow
  {
    size_t index{0};
    NodeId subject;
    Duration revisedInterval{0};
    uint32_t revisedQueueSize{0};
    DataChangeTrigger trigger{DataChangeTrigger::StatusValue};
    DeadbandType deadbandType{DeadbandType::None};
    double deadbandValue{0.0};
    bool keepHeldEuRange{false};
    bool readsEuRange{false};
    uint64_t euRangeGeneration{0};
    std::optional<EuRangeRead> euRange;
  };

  std::vector<ModifyRow> rows;
  std::vector<size_t> lookedUp;
  for (size_t i = 0; i < itemsToModify.size(); ++i)
  {
    const auto& params = itemsToModify[i].requested_parameters();
    auto it = mMonitoredItems.find(itemsToModify[i].monitored_item_id());
    if (it == mMonitoredItems.end())
    {
      results[i].status_code() = StatusCode{Status::BadMonitoredItemIdInvalid};
      continue;
    }
    const MonitoredItem& current = *it->second;
    const auto attributeId = utils::from_underlying<AttributeId>(current.itemToMonitor.attribute_id());
    ModifyRow row;
    row.index = i;
    row.subject = current.itemToMonitor.node_id();
    row.revisedInterval =
      revise_sampling_interval(params.sampling_interval(), publishInterval, minSampling, maxSampling);
    row.revisedQueueSize = revise_queue_size(params.queue_size(), maxQueueSize);
    auto filter = parse_data_change_filter(params.filter(), row.subject, attributeId);
    if (filter.statusCode.is_bad())
    {
      results[i].status_code() = filter.statusCode;
      continue;
    }
    row.trigger = filter.trigger;
    row.deadbandType = filter.deadbandType;
    row.deadbandValue = filter.deadbandValue;
    // A PercentDeadband needs the EURange as a create does (Part 8 6.2, Table 29). An item that already has a
    // PercentDeadband with a usable range keeps it, current through its SemanticsChanged marks; any other
    // item reads it.
    if (filter.deadbandType == DeadbandType::Percent)
    {
      if (current.deadbandType == DeadbandType::Percent && current.hasEuRange)
      {
        row.keepHeldEuRange = true;
      }
      else
      {
        row.readsEuRange = true;
        row.euRangeGeneration = current.euRangeGeneration;
      }
    }
    if (filter.deadbandType == DeadbandType::Absolute || row.readsEuRange)
    {
      lookedUp.push_back(rows.size());
    }
    rows.push_back(std::move(row));
  }

  if (!lookedUp.empty())
  {
    std::vector<NodeId> subjects;
    subjects.reserve(lookedUp.size());
    for (const size_t r : lookedUp)
    {
      subjects.push_back(rows[r].subject);
    }
    auto found = co_await await_step<std::vector<NodeAccessorResult>>(
      [&addressSpace, &requestInfo, &subjects](auto completion)
      { namespace_calls::find_nodes(addressSpace, requestInfo, subjects, std::move(completion)); });
    if (!mModifyRunning)
    {
      co_return;
    }

    // The DataTypes of the AbsoluteDeadband rows and the EURanges of the PercentDeadband rows, decided
    // together.
    std::vector<size_t> absoluteRows;
    std::vector<size_t> absoluteType;
    std::vector<NodeId> types;
    std::map<NodeId, size_t> typeSlot;
    std::vector<size_t> percentRows;
    std::vector<NodeAccessor> percentVariables;
    for (size_t k = 0; k < lookedUp.size(); ++k)
    {
      const auto& row = rows[lookedUp[k]];
      const bool good = k < found.size() && found[k].is_good();
      if (!good)
      {
        const StatusCode answer =
          k < found.size() ? found[k].status_code() : StatusCode{Status::BadInternalError};
        if (!answer.is_bad())
        {
          // An Uncertain answer holds no Node: the row is refused, and no other row is affected (DL-69 (D2)).
          results[row.index].status_code() = lookup_answer_uncertain(row.subject, answer);
        }
        else if (row.readsEuRange)
        {
          results[row.index].status_code() = percent_deadband_refusal(row.subject, answer);
        }
        // An AbsoluteDeadband on a Variable that cannot be looked up is undecidable, and not refused.
        continue;
      }
      if (row.readsEuRange)
      {
        percentRows.push_back(lookedUp[k]);
        percentVariables.push_back(found[k].value());
        continue;
      }
      const auto nodeDescription = ua::detail::NodeAccessorRoute::attributes(found[k].value());
      if (!nodeDescription.is_good() || nodeDescription.value().node_class() != NodeClass::Variable)
      {
        continue;
      }
      const NodeId* dataType = nodeDescription.value().data_type();
      if (dataType == nullptr || dataType->is_null())
      {
        continue;
      }
      const auto [entry, added] = typeSlot.try_emplace(*dataType, types.size());
      if (added)
      {
        types.push_back(*dataType);
      }
      absoluteRows.push_back(lookedUp[k]);
      absoluteType.push_back(entry->second);
    }

    // Both started before either is awaited.
    auto typeDecision = decide_numeric_data_types(addressSpace, requestInfo, std::move(types));
    auto euRangeResolution = resolve_eu_ranges(
      addressSpace, requestInfo, std::move(percentVariables), capabilities.operationLimits.maxNodesPerBrowse);
    const auto nonNumeric = co_await std::move(typeDecision);
    const auto euRanges = co_await std::move(euRangeResolution);
    if (!mModifyRunning)
    {
      co_return;
    }

    for (size_t a = 0; a < absoluteRows.size(); ++a)
    {
      const auto& row = rows[absoluteRows[a]];
      if (absoluteType[a] < nonNumeric.size() && nonNumeric[absoluteType[a]])
      {
        results[row.index].status_code() = absolute_deadband_on_non_numeric_value(row.subject);
      }
    }
    for (size_t p = 0; p < percentRows.size(); ++p)
    {
      auto& row = rows[percentRows[p]];
      const auto euRange = p < euRanges.size() ? eu_range_from(euRanges[p])
                                               : Result<EuRangeRead>{StatusCode{Status::BadInternalError}};
      if (!euRange.is_good() || !usable_eu_range(euRange.value().low, euRange.value().high))
      {
        results[row.index].status_code() = percent_deadband_refusal(row.subject, euRange.status_code());
        continue;
      }
      row.euRange = euRange.value();
    }
  }

  std::vector<PendingModify> validModifies;
  validModifies.reserve(rows.size());
  std::map<uint16_t, std::vector<std::pair<size_t, MonitoringModifyItem>>> byNamespace;
  for (const auto& row : rows)
  {
    if (results[row.index].status_code().is_bad())
    {
      continue;
    }
    const auto& modReq = itemsToModify[row.index];
    const auto& params = modReq.requested_parameters();
    // The item may have been deleted while its Variable was being looked up.
    auto it = mMonitoredItems.find(modReq.monitored_item_id());
    if (it == mMonitoredItems.end())
    {
      results[row.index].status_code() = StatusCode{Status::BadMonitoredItemIdInvalid};
      continue;
    }

    auto& item = *it->second;
    PendingModify pending;
    pending.keepHeldEuRange = row.keepHeldEuRange;
    if (row.euRange)
    {
      pending.euRangeLow = row.euRange->low;
      pending.euRangeHigh = row.euRange->high;
      pending.euRangeGeneration = row.euRangeGeneration;
      pending.euRangeRead = true;
    }
    pending.index = row.index;
    pending.monitoredItemId = item.id;
    pending.revisedSamplingInterval = row.revisedInterval;
    pending.revisedQueueSize = row.revisedQueueSize;
    pending.discardOldest = params.discard_oldest();
    pending.trigger = row.trigger;
    pending.deadbandType = row.deadbandType;
    pending.deadbandValue = row.deadbandValue;
    pending.clientHandle = params.client_handle();
    pending.diagnosticInfoMask = request.request_header().return_diagnostics();
    validModifies.push_back(pending);

    if (item.namespaceHandle == 0)
    {
      apply_pending_modify(item, validModifies.back());
    }
    else
    {
      MonitoringModifyItem modifyItem;
      modifyItem.handle = item.namespaceHandle;
      modifyItem.samplingInterval = pending.revisedSamplingInterval;
      modifyItem.queueSize = pending.revisedQueueSize;
      byNamespace[item.namespaceIndex].emplace_back(validModifies.size() - 1, modifyItem);
    }
  }

  // Every namespace is asked at once (NR-26), so the modify waits for its slowest namespace rather than for
  // the sum of them. Each part writes only its own rows; every part is awaited before this frame, which they
  // borrow, can end.
  std::vector<ua::async::Task<>> units;
  units.reserve(byNamespace.size());
  for (const auto& [namespaceIndex, nsItems] : byNamespace)
  {
    units.push_back(
      modify_in_namespace(addressSpace, requestInfo, namespaceIndex, nsItems, results, validModifies));
  }
  for (auto& unit : units)
  {
    co_await std::move(unit);
  }

  if (mModifyRunning)
  {
    finish_modify(std::move(results), validModifies);
  }
  co_return;
}

ua::async::Task<> Subscription::modify_in_namespace(AddressSpace& addressSpace,
  const RequestInfo& requestInfo, uint16_t namespaceIndex,
  const std::vector<std::pair<size_t, MonitoringModifyItem>>& nsItems,
  std::vector<MonitoredItemModifyResult>& results, std::vector<PendingModify>& validModifies)
{
  BatchResult<MonitoringModifyItemResult> batch;
  auto ns = addressSpace.namespace_array().get_namespace(namespaceIndex);
  if (!ns)
  {
    batch.batchStatus = VoidResult{StatusCode{Status::BadInternalError,
      ErrorDetail::build("MonitoringModifyNamespaceUnavailable",
        "Monitoring Namespace is unavailable",
        "Subscription.modify_monitored_items")
        .context(ContextKeys::namespaceIndex, namespaceIndex)}};
  }
  else
  {
    // The namespace borrows this storage until it answers, and the part stays suspended in the frame that
    // holds it until then.
    std::vector<MonitoringModifyItem> modifyItems;
    modifyItems.reserve(nsItems.size());
    for (const auto& nsItem : nsItems)
    {
      modifyItems.push_back(nsItem.second);
    }

    // The entry guards the call (NR-45 rule 3): its answer is a Bad batch status or one result per item,
    // and it answers once, a throw included.
    batch = co_await await_step<BatchResult<MonitoringModifyItemResult>>(
      [&ns, &requestInfo, &modifyItems](auto completion)
      { ua::detail::MonitoringEntry::modify(ns, requestInfo, modifyItems, std::move(completion)); });
  }

  if (!mModifyRunning)
  {
    // Something else ended this modify and answered its caller.
    co_return;
  }

  if (batch.batchStatus.is_bad())
  {
    for (const auto& nsItem : nsItems)
    {
      const auto requestIndex = validModifies[nsItem.first].index;
      results[requestIndex].status_code() = batch.batchStatus.status_code();
    }
    co_return;
  }

  // The entry answered one result per item.
  const auto& nsResults = batch.items;
  for (size_t j = 0; j < nsItems.size() && j < nsResults.size(); ++j)
  {
    auto& pending = validModifies[nsItems[j].first];

    const auto& nsResult = nsResults[j];
    if (!nsResult.has_value())
    {
      const auto* refused = find_monitored_item(pending.monitoredItemId);
      results[pending.index].status_code() = refused_monitoring_answer(
        nsResult.status_code(), refused ? refused->itemToMonitor.node_id() : NodeId{});
      continue;
    }
    // A Good subcode or an Uncertain code with a result changes the item, which answers that code.
    pending.answered = nsResult.status_code();
    if (nsResult.value().revisedSamplingInterval > 0)
    {
      pending.revisedSamplingInterval = nsResult.value().revisedSamplingInterval;
    }

    // Looked up again rather than remembered. A delete is not refused while a modify is running,
    // and it erases the MonitoredItems it names - so the item this row is about can be gone by the
    // time its namespace answers, and the row is then about an item that no longer exists.
    auto* item = find_monitored_item(pending.monitoredItemId);
    if (!item)
    {
      results[pending.index].status_code() = StatusCode{Status::BadMonitoredItemIdInvalid};
      continue;
    }
    apply_pending_modify(*item, pending);
  }
}

void Subscription::apply_pending_modify(MonitoredItem& item, const PendingModify& pending)
{
  const bool hadReportable = item.has_reportable_notifications();
  const uint32_t oldQueueSize = item.queueSize;

  item.samplingInterval = pending.revisedSamplingInterval;
  item.queueSize = pending.revisedQueueSize;
  item.discardOldest = pending.discardOldest;
  item.trigger = pending.trigger;
  item.deadbandType = pending.deadbandType;
  item.deadbandValue = pending.deadbandValue;
  item.clientHandle = pending.clientHandle;
  item.diagnosticInfoMask = pending.diagnosticInfoMask;
  // Part 4 5.12.3.1: a changed setting applies at once, the PercentDeadband's range with it. An item that
  // keeps its PercentDeadband keeps the range it holds, which a re-read may have replaced meanwhile.
  if (!pending.keepHeldEuRange)
  {
    item.hasEuRange = pending.deadbandType == DeadbandType::Percent;
    item.euRangeLow = pending.euRangeLow;
    item.euRangeHigh = pending.euRangeHigh;
  }
  // Marked while this modify's read and the namespace's answer were outstanding: what was read may be
  // older than the mark, so it is read again.
  if (pending.euRangeRead && item.euRangeGeneration != pending.euRangeGeneration)
  {
    reread_eu_range(item);
  }

  if (pending.revisedQueueSize < oldQueueSize && item.queue.size() > pending.revisedQueueSize)
  {
    const bool sidecarsAligned = item.queuedUserIndependentValues.size() == item.queue.size();
    // A StructureChanged bit on a discarded notification is set on the kept notification that follows it, as
    // enqueue does on an overflow (OPC 10000-4 7.39.1 Table 180): the new front when the oldest are
    // discarded, the latest when the entries before it are.
    const auto carriesStructureChange = [](const DataValue& value)
    {
      return value.status().has_value() && value.status()->structure_changed();
    };
    const auto setStructureChange = [](DataValue& value)
    {
      value.status().emplace(value.status().value_or(StatusCode{})).structure_changed(true);
    };
    bool discardedStructureChange = false;
    if (item.discardOldest)
    {
      while (item.queue.size() > pending.revisedQueueSize)
      {
        discardedStructureChange = discardedStructureChange || carriesStructureChange(item.queue.front());
        item.queue.pop_front();
        if (sidecarsAligned)
          item.queuedUserIndependentValues.pop_front();
      }
      if (discardedStructureChange && !item.queue.empty())
      {
        setStructureChange(item.queue.front());
        if (sidecarsAligned)
        {
          auto& retainedValue = item.queuedUserIndependentValues.front();
          if (retainedValue)
            setStructureChange(retainedValue.value());
        }
      }
    }
    else
    {
      // Runtime overflow with discardOldest=false replaces the tail, so that slot always carries
      // the latest sample. Preserve the same queue shape when shrinking: keep the oldest
      // revisedQueueSize - 1 entries and the current tail.
      auto latest = std::move(item.queue.back());
      std::optional<DataValue> latestUserIndependent;
      if (sidecarsAligned)
      {
        latestUserIndependent = std::move(item.queuedUserIndependentValues.back());
        item.queuedUserIndependentValues.pop_back();
      }
      item.queue.pop_back();
      while (item.queue.size() >= pending.revisedQueueSize)
      {
        discardedStructureChange = discardedStructureChange || carriesStructureChange(item.queue.back());
        item.queue.pop_back();
        if (sidecarsAligned)
          item.queuedUserIndependentValues.pop_back();
      }
      if (discardedStructureChange)
      {
        setStructureChange(latest);
        if (latestUserIndependent)
          setStructureChange(*latestUserIndependent);
      }
      item.queue.push_back(std::move(latest));
      if (sidecarsAligned)
        item.queuedUserIndependentValues.push_back(std::move(latestUserIndependent));
    }
    if (!sidecarsAligned)
      item.queuedUserIndependentValues.assign(item.queue.size(), std::nullopt);

    // SVR-MI-GEN-024: a queue of size 1 never reports Overflow. The entry kept here may carry the bit
    // from the larger queue it was trimmed from, so a shrink to 1 clears it, as enqueue never sets it.
    if (pending.revisedQueueSize == 1)
    {
      const auto clearOverflow = [](DataValue& value)
      {
        if (value.status().has_value())
          value.status()->overflow(false);
      };
      for (auto& queued : item.queue)
        clearOverflow(queued);
      for (auto& retained : item.queuedUserIndependentValues)
        if (retained)
          clearOverflow(*retained);
    }
  }

  const bool nowReportable = item.has_reportable_notifications();
  if (hadReportable && !nowReportable && mReportableItemCount > 0)
  {
    --mReportableItemCount;
  }
  else if (!hadReportable && nowReportable)
  {
    ++mReportableItemCount;
  }
}

Subscription::ModifyMonitoredItemsCallback Subscription::take_modify_completion()
{
  // Whoever gets here first ends the modify and answers it once. @see take_delete_completion
  auto callback = std::move(mModifyCompletion);
  mModifyCompletion = nullptr;
  mModifyRunning = false;
  mModifyItemCount = 0;
  // A namespace still working for the modify may stop: nothing it answers from here on is read.
  if (auto cancelled = std::exchange(mModifyCancelled, nullptr))
  {
    cancelled->store(true, std::memory_order_release);
  }

  // What the slot pins is the root task's parameters - the client's whole request, the caller's
  // AddressSpace handle and its two configuration snapshots - and nothing would release them until
  // the NEXT modify overwrote the slot.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation = mModifyGeneration](Subscription& self)
    {
      if (self.mModifyGeneration == generation && !self.mModifyRunning)
      {
        self.mModifyTask = {};
      }
    })();

  return callback;
}

void Subscription::finish_modify(
  std::vector<MonitoredItemModifyResult> results, const std::vector<PendingModify>& validModifies)
{
  auto cb = take_modify_completion();

  // The rows that survived validation AND were not failed by a namespace get the code their namespace
  // answered (plain Good, a Good subcode or an Uncertain code) and their revised values together, here, so a
  // row never carries half an answer. Entries already holding a bad code are left alone.
  for (const auto& pending : validModifies)
  {
    auto& result = results[pending.index];
    if (result.status_code().is_bad())
    {
      continue;
    }
    result.status_code() = pending.answered;
    result.revised_sampling_interval() = pending.revisedSamplingInterval;
    result.revised_queue_size() = pending.revisedQueueSize;
  }

  mHasNotifications.store(notifications_available(), std::memory_order_release);
  update_info();

  if (cb)
  {
    cb(std::move(results));
  }
}

void Subscription::fail_modify(StatusCode status)
{
  // Ends the modify with one status for every row it was given. Read the count before ending the
  // modify, because ending it is what releases the count along with everything else.
  if (!mModifyRunning)
  {
    return;
  }
  const size_t requestSize = mModifyItemCount;
  auto cb = take_modify_completion();

  std::vector<MonitoredItemModifyResult> failed(requestSize);
  for (auto& r : failed)
  {
    r.status_code() = status;
  }
  if (cb)
  {
    cb(std::move(failed));
  }
}

ua::async::Task<> Subscription::yield_strand()
{
  // `await_step` posts the answer, so answering it inline is a post and nothing more: the strand
  // turn this is called from ends here, and whatever else that strand owes - the publishing timer
  // above all - gets its turn before the body resumes.
  co_await await_step<std::monostate>([](auto completion) { completion(std::monostate{}); });
}

// --- SetMonitoringMode ---

/// One monitoring-mode change, in the order the handler chain walked it.
void Subscription::start_set_monitoring_mode(std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode)
{
  // A task is EAGER, and most changes finish without ever suspending - nothing is being taken out of
  // Disabled, so there is no permission to decide. Such a change fires its answer before this
  // returns, and the answer may start the next one; the generation says whether the slot is still
  // ours to fill. @see start_delete
  const uint64_t generation = ++mSetMonitoringModeGeneration;
  auto change = run_set_monitoring_mode(std::move(monitoredItemIds), newMode);
  if (mSetMonitoringModeGeneration == generation)
  {
    mSetMonitoringModeTask = std::move(change);
  }
}

ua::async::Task<> Subscription::run_set_monitoring_mode(
  std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode)
{
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise
  // nobody reads. The client's SetMonitoringMode would go unanswered and `mSetMonitoringModeRunning`
  // would stay latched, which stops this subscription ever re-authorizing its items again - the
  // periodic recheck skips its cycle and a mandatory one is refused BadServerTooBusy.
  try
  {
    co_await walk_set_monitoring_mode(monitoredItemIds, newMode);
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the change and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mSetMonitoringModeRunning)
        {
          fail_set_monitoring_mode(ua::exception_to_status_code(std::current_exception()));
        }
      })();
  }
  co_return;
}

ua::async::Task<> Subscription::walk_set_monitoring_mode(
  const std::vector<IntegerId>& monitoredItemIds, MonitoringMode newMode)
{
  std::vector<StatusCode> results(monitoredItemIds.size());
  std::vector<PendingEnable> pendingEnables;

  // Everything a mode change can decide on its own it decides here, in one turn. Only taking an item
  // OUT of Disabled needs someone else's answer, because the item's permissions have to be decided
  // again before it may report values; those items are collected and the rest are already done.
  for (size_t resultIndex = 0; resultIndex < monitoredItemIds.size(); ++resultIndex)
  {
    auto it = mMonitoredItems.find(monitoredItemIds[resultIndex]);
    if (it == mMonitoredItems.end())
    {
      results[resultIndex] = StatusCode{Status::BadMonitoredItemIdInvalid};
      continue;
    }

    auto& item = *it->second;
    const auto oldMode = item.monitoringMode;

    if (oldMode == newMode)
    {
      results[resultIndex] = StatusCode{Status::Good};
      continue;
    }

    if (oldMode == MonitoringMode::Disabled && newMode != MonitoringMode::Disabled)
    {
      const NodeId nodeId = item.itemToMonitor.node_id();
      pendingEnables.push_back(PendingEnable{.resultIndex = resultIndex,
        .monitoredItemId = item.id,
        .nodeId = nodeId,
        .operation = monitored_item_operation(item),
        .resolvedNode = std::nullopt,
        .verdict = AccessControl::Verdict{.subject = nodeId,
          .operation = monitored_item_operation(item),
          .cause = StatusCode{Status::BadUserAccessDenied}}});
      continue;
    }

    const bool hadReportable = item.has_reportable_notifications();
    if (newMode == MonitoringMode::Disabled)
    {
      // SVR-MI-GEN-014: Transition to Disabled clears the queue.
      item.queue.clear();
      item.queuedUserIndependentValues.clear();
      item.eventQueue.clear();
      item.overflowEventInserted = false;
      item.overflowEventQueued = false;
      item.overflowEventPending = false;  // a loss from before the clear is not announced after it
      item.triggeredReportPending = false;
      item.lastQueuedValue.reset();
      if (item.isEventItem)
        discard_pending_event_deliveries(item.id);
      // A pending SemanticsChanged arming must not leak across a disable/re-enable (9): the queue
      // it would have flagged is gone. Nor a StructureChanged bit owed: a Disabled item samples nothing.
      item.pendingSemanticChange = false;
      item.pendingStructureChange = false;
    }

    item.monitoringMode = newMode;

    const bool nowReportable = item.has_reportable_notifications();
    if (hadReportable && !nowReportable && mReportableItemCount > 0)
    {
      --mReportableItemCount;
    }
    else if (!hadReportable && nowReportable)
    {
      ++mReportableItemCount;
    }

    results[resultIndex] = StatusCode{Status::Good};
  }

  mHasNotifications.store(notifications_available(), std::memory_order_release);
  update_info();

  if (pendingEnables.empty())
  {
    finish_set_monitoring_mode(std::move(results));
    co_return;
  }

  // A periodic or mandatory refresh that began first owns the current authorization transition. Fail
  // only the rows that require a fresh decision; immediate disable/no-op rows above remain effective.
  if (mAccessRecheckRunning)
  {
    const auto busy = StatusCode{Status::BadInvalidState,
      ErrorDetail::build("SetMonitoringModeReauthorizationBusy",
        "A monitored item cannot be re-enabled while another authorization refresh is active",
        "Subscription")};
    for (const auto& pending : pendingEnables)
      results[pending.resultIndex] = busy;
    finish_set_monitoring_mode(std::move(results));
    co_return;
  }

  std::optional<AddressSpace> addressSpace;
  std::optional<SessionAccessControl> accessControl;

  // Scoped, because the session's security context is held WEAKLY on purpose and this is the only
  // moment it needs to be strong. A body's locals live to the end of the body, and a body that
  // suspends keeps them across every suspension - so a lock left at body scope here would hold the
  // session alive across two collaborator round trips, which R7 forbids and which the chain this
  // replaces did not do: it let both go when its first handler returned. What survives the scope is
  // an identity that has already been decided and an AddressSpace handle the calls need.
  {
    auto securityContext = mRecheckSecurityContext.lock();
    auto recheckAddressSpace = mRecheckAddressSpace.lock();
    if (auto* firstItem = find_monitored_item(pendingEnables.front().monitoredItemId))
    {
      if (!securityContext)
        securityContext = firstItem->accessSecurityContext.lock();
      if (!recheckAddressSpace)
        recheckAddressSpace = firstItem->accessAddressSpace.lock();
    }

    if (securityContext && recheckAddressSpace)
    {
      addressSpace = *recheckAddressSpace;
      accessControl =
        SessionAccessControl::create(*securityContext, *recheckAddressSpace, mAccessControlTimeout, mLogger);
    }
  }

  if (!addressSpace || !accessControl)
  {
    for (auto& pending : pendingEnables)
    {
      pending.verdict = AccessControl::Verdict{.subject = pending.nodeId,
        .operation = pending.operation,
        .permitted = false,
        .cause = monitoring_mode_authorization_denied(pending.nodeId,
          "SetMonitoringModeAuthorizationContextUnavailable",
          "The current Session identity or AddressSpace is unavailable while re-enabling a monitored item",
          StatusCode{Status::BadInternalError})};
    }
    apply_set_monitoring_mode(pendingEnables, newMode, accessControl, results);
    finish_set_monitoring_mode(std::move(results));
    co_return;
  }

  // Every item being re-enabled is resolved in ONE call and authorized in ONE call. Which item a
  // result belongs to is its position, so both answers are checked for cardinality before they are
  // believed - a collaborator that returns the wrong number of them would otherwise silently shift
  // every decision onto the wrong item.
  std::vector<NodeId> nodeIds;
  nodeIds.reserve(pendingEnables.size());
  for (const auto& pending : pendingEnables)
    nodeIds.push_back(pending.nodeId);

  auto batch = co_await await_step<BatchResult<NodeAccessorResult>>([&addressSpace, &nodeIds](auto completion)
    { addressSpace->find_nodes_async(nodeIds, std::move(completion)); });

  if (!mSetMonitoringModeRunning)
  {
    // Something else ended this change and answered its caller.
    co_return;
  }

  std::vector<AccessControl::Item> resolvedItems;
  std::vector<size_t> resolvedPendingIndices;

  if (batch.batchStatus.is_bad() || batch.items.size() != pendingEnables.size())
  {
    StatusCode cause = batch.batchStatus.is_bad()
                         ? batch.batchStatus.status_code()
                         : StatusCode{Status::BadUnexpectedError,
                             ErrorDetail::build("SetMonitoringModeResolutionCardinalityMismatch",
                               "Monitored-item subject resolution returned the wrong number of results",
                               "Subscription")
                               .context(ContextKeys::expected, std::to_string(pendingEnables.size()))
                               .context(ContextKeys::actual, std::to_string(batch.items.size()))};
    for (auto& pending : pendingEnables)
    {
      pending.verdict = AccessControl::Verdict{.subject = pending.nodeId,
        .operation = pending.operation,
        .permitted = false,
        .cause = monitoring_mode_authorization_denied(pending.nodeId,
          "SetMonitoringModeSubjectResolutionFailed",
          "The monitored item's authorization subject could not be resolved while re-enabling",
          cause)};
    }
  }
  else
  {
    resolvedItems.reserve(batch.items.size());
    resolvedPendingIndices.reserve(batch.items.size());
    for (size_t pendingIndex = 0; pendingIndex < batch.items.size(); ++pendingIndex)
    {
      auto& pending = pendingEnables[pendingIndex];
      auto& resolved = batch.items[pendingIndex];
      if (!resolved.is_good())
      {
        pending.verdict = AccessControl::Verdict{.subject = pending.nodeId,
          .operation = pending.operation,
          .permitted = false,
          .cause = monitoring_mode_authorization_denied(pending.nodeId,
            "SetMonitoringModeSubjectResolutionFailed",
            "The monitored item's authorization subject could not be resolved while re-enabling",
            resolved.status_code())};
        continue;
      }

      pending.resolvedNode = std::move(resolved).value();
      resolvedPendingIndices.push_back(pendingIndex);
      resolvedItems.push_back(AccessControl::Item{*pending.resolvedNode, pending.operation});
    }
  }

  // Nothing resolved: every item already carries the verdict that says why, and asking for a decision
  // about no subjects would be a round trip for nothing.
  if (!resolvedItems.empty())
  {
    auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
      [&accessControl, &resolvedItems](auto completion)
      { accessControl->authorize_async(RequestInfo{}, resolvedItems, std::move(completion)); });

    if (!mSetMonitoringModeRunning)
    {
      co_return;
    }

    if (verdicts.size() != resolvedPendingIndices.size())
    {
      const StatusCode cause{Status::BadUnexpectedError,
        ErrorDetail::build("SetMonitoringModeAuthorizationCardinalityMismatch",
          "Monitored-item authorization returned the wrong number of verdicts",
          "Subscription")
          .context(ContextKeys::expected, std::to_string(resolvedPendingIndices.size()))
          .context(ContextKeys::actual, std::to_string(verdicts.size()))};
      for (const size_t pendingIndex : resolvedPendingIndices)
      {
        auto& pending = pendingEnables[pendingIndex];
        pending.verdict = AccessControl::Verdict{.subject = pending.nodeId,
          .operation = pending.operation,
          .permitted = false,
          .cause = monitoring_mode_authorization_denied(pending.nodeId,
            "SetMonitoringModeAuthorizationFailed",
            "The monitored item's permission decision was incomplete while re-enabling",
            cause)};
      }
    }
    else
    {
      for (size_t verdictIndex = 0; verdictIndex < verdicts.size(); ++verdictIndex)
      {
        const size_t pendingIndex = resolvedPendingIndices[verdictIndex];
        pendingEnables[pendingIndex].verdict = std::move(verdicts[verdictIndex]);
      }
    }
  }

  apply_set_monitoring_mode(pendingEnables, newMode, accessControl, results);
  finish_set_monitoring_mode(std::move(results));
}

void Subscription::apply_set_monitoring_mode(std::vector<PendingEnable>& pendingEnables,
  MonitoringMode newMode, const std::optional<SessionAccessControl>& accessControl,
  std::vector<StatusCode>& results)
{
  for (auto& pending : pendingEnables)
  {
    auto* item = find_monitored_item(pending.monitoredItemId);
    if (!item || item->itemToMonitor.node_id() != pending.nodeId)
    {
      results[pending.resultIndex] = StatusCode{Status::BadMonitoredItemIdInvalid};
      continue;
    }
    if (item->monitoringMode == newMode)
    {
      results[pending.resultIndex] = StatusCode{Status::Good};
      continue;
    }
    if (item->monitoringMode != MonitoringMode::Disabled)
    {
      results[pending.resultIndex] = monitoring_mode_change_busy();
      continue;
    }

    auto verdict = std::move(pending.verdict);
    if (verdict.subject != pending.nodeId || verdict.operation != pending.operation ||
        (verdict.permitted && (!pending.resolvedNode || !accessControl)))
    {
      verdict = AccessControl::Verdict{.subject = pending.nodeId,
        .operation = pending.operation,
        .permitted = false,
        .cause = monitoring_mode_authorization_denied(pending.nodeId,
          "SetMonitoringModeAuthorizationAssociationInvalid",
          "The permission decision was not associated with the monitored item's exact subject",
          StatusCode{Status::BadUnexpectedError})};
    }

    std::shared_ptr<EventBus> eventBus;
    if (item->isEventItem && verdict.permitted && item->eventBusHandle == 0)
    {
      eventBus = mRecheckEventBus.lock();
      if (!eventBus)
      {
        verdict = AccessControl::Verdict{.subject = pending.nodeId,
          .operation = pending.operation,
          .permitted = false,
          .cause = monitoring_mode_authorization_denied(pending.nodeId,
            "SetMonitoringModeEventBusUnavailable",
            "The EventBus is unavailable while restoring an Event monitored item",
            StatusCode{Status::BadInternalError})};
      }
    }

    if (pending.resolvedNode)
      item->accessControlNode = *pending.resolvedNode;
    if (accessControl)
    {
      item->accessSnapshot = MonitoredAccessSnapshot{accessControl->identity()->key(), verdict};
    }
    else
    {
      item->accessSnapshot.reset();
    }

    if (item->isEventItem)
    {
      if (!verdict.permitted && item->eventBusHandle != 0)
      {
        if (auto registeredEventBus = mRecheckEventBus.lock())
          registeredEventBus->deregister_event_item(item->eventBusHandle);
        item->eventBusHandle = 0;
      }
      else if (verdict.permitted && item->eventBusHandle == 0)
      {
        register_event_monitored_item(*item, *eventBus);
      }
    }

    const bool hadReportable = item->has_reportable_notifications();
    item->monitoringMode = newMode;

    // A Disabled-to-enabled transition reports one initial value. Projection consumes the fresh
    // verdict directly; it never re-probes the namespace and never reconstructs from an
    // identity-filtered value.
    if (!item->isEventItem && item->lastSentValue.has_value())
    {
      auto userIndependentValue = latest_user_independent_value_or_denied(*item);
      DataValue projected =
        verdict.permitted && accessControl && item->accessControlNode
          ? project_monitored_value(*item, userIndependentValue, mAccessControlTimeout, mLogger)
          : DataValue{verdict.cause};
      item->enqueue_initial(std::move(projected), std::move(userIndependentValue));
    }

    const bool nowReportable = item->has_reportable_notifications();
    if (hadReportable && !nowReportable && mReportableItemCount > 0)
      --mReportableItemCount;
    else if (!hadReportable && nowReportable)
      ++mReportableItemCount;
    results[pending.resultIndex] = StatusCode{Status::Good};
  }

  mHasNotifications.store(notifications_available(), std::memory_order_release);
  update_info();
}

Subscription::SetMonitoringModeCallback Subscription::take_set_monitoring_mode_completion()
{
  // Whoever gets here first ends the change and answers it once - the body on its way out, `close()`,
  // or ~Subscription answering for a body that can no longer be asked. Clearing the flag is what an
  // in-flight body reads to discover it was one of the ones that did not get there first.
  auto callback = std::move(mSetMonitoringModeCompletion);
  mSetMonitoringModeCompletion = nullptr;
  mSetMonitoringModeRunning = false;
  mSetMonitoringModeItemCount = 0;

  // What the slot pins is the ROOT task's parameters - here the client's list of monitored-item ids,
  // whose length the client chooses - and nothing would release them until the NEXT change overwrote
  // the slot, which for most subscriptions is never. The working state is not among them: the
  // address space handle, the identity and the resolved subjects are LOCALS of the nested body, and
  // a local goes when the body ends. Released on a later turn, because this is reached from inside
  // that very frame, and guarded by the generation because the answer may start the next change
  // before that turn runs.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation = mSetMonitoringModeGeneration](Subscription& self)
    {
      if (self.mSetMonitoringModeGeneration == generation && !self.mSetMonitoringModeRunning)
      {
        self.mSetMonitoringModeTask = {};
      }
    })();

  return callback;
}

void Subscription::finish_set_monitoring_mode(std::vector<StatusCode> results)
{
  auto callback = take_set_monitoring_mode_completion();
  if (callback)
    callback(std::move(results));
}

void Subscription::fail_set_monitoring_mode(StatusCode status)
{
  // Ends the change with one status for every id it was given. Read the count before ending the
  // change, because ending it is what releases the count along with everything else.
  if (!mSetMonitoringModeRunning)
    return;
  const size_t itemCount = mSetMonitoringModeItemCount;
  auto callback = take_set_monitoring_mode_completion();
  std::vector<StatusCode> results(itemCount, std::move(status));
  if (callback)
    callback(std::move(results));
}

// --- SetTriggering ---

Subscription::SetTriggeringResult Subscription::set_triggering(IntegerId triggeringItemId,
  const std::vector<IntegerId>& linksToAdd, const std::vector<IntegerId>& linksToRemove)
{
  SetTriggeringResult result;

  // Validate triggering item exists. An invalid triggeringItemId is a service-level failure
  // (Part 4 Table 79 - Bad_MonitoredItemIdInvalid is a SetTriggering Service Result Code).
  if (mMonitoredItems.find(triggeringItemId) == mMonitoredItems.end())
  {
    result.triggeringItemInvalid = true;
    result.removeResults.resize(linksToRemove.size(), StatusCode{Status::BadMonitoredItemIdInvalid});
    result.addResults.resize(linksToAdd.size(), StatusCode{Status::BadMonitoredItemIdInvalid});
    return result;
  }

  // Process removes first (SVC-SetTrig-002).
  result.removeResults.reserve(linksToRemove.size());
  for (auto linkedId : linksToRemove)
  {
    auto linkIt = mTriggerLinks.find(triggeringItemId);
    if (linkIt != mTriggerLinks.end() && linkIt->second.erase(linkedId) > 0)
    {
      result.removeResults.push_back(StatusCode{Status::Good});
      // Clean up empty sets.
      if (linkIt->second.empty())
      {
        mTriggerLinks.erase(linkIt);
      }
    }
    else
    {
      result.removeResults.push_back(StatusCode{Status::BadMonitoredItemIdInvalid});
    }
  }

  // Process adds.
  result.addResults.reserve(linksToAdd.size());
  for (auto linkedId : linksToAdd)
  {
    if (mMonitoredItems.find(linkedId) != mMonitoredItems.end())
    {
      mTriggerLinks[triggeringItemId].insert(linkedId);
      result.addResults.push_back(StatusCode{Status::Good});
    }
    else
    {
      result.addResults.push_back(StatusCode{Status::BadMonitoredItemIdInvalid});
    }
  }

  return result;
}

// --- SubscriptionInfo snapshot ---

SubscriptionInfo Subscription::get_info() const
{
  const std::lock_guard lock(mInfoMutex);
  return mCachedInfo;
}

void Subscription::update_info()
{
  // Compute monitored-item-derived diagnostics off-lock: distinct sampling intervals (with item +
  // disabled counts), total disabled items, and aggregate queue-overflow totals. Overflow totals
  // stay monotonic by adding the counts carried over from already-removed items.
  std::vector<SamplingIntervalEntry> intervals;
  uint32_t disabledCount = 0;
  uint32_t dataOverflow = mRemovedDataOverflowCount;
  uint32_t eventOverflow = mRemovedEventOverflowCount;
  for (const auto& [miId, item] : mMonitoredItems)
  {
    const bool disabled = (item->monitoringMode == MonitoringMode::Disabled);
    if (disabled)
      ++disabledCount;
    dataOverflow += item->dataQueueOverflowCount;
    eventOverflow += item->eventQueueOverflowCount;

    auto it = std::find_if(intervals.begin(),
      intervals.end(),
      [&](const SamplingIntervalEntry& e) { return e.samplingInterval == item->samplingInterval; });
    if (it == intervals.end())
      intervals.push_back(SamplingIntervalEntry{item->samplingInterval, 1, disabled ? 1u : 0u});
    else
    {
      ++it->monitoredItemCount;
      if (disabled)
        ++it->disabledMonitoredItemCount;
    }
  }

  // Report this Subscription's per-interval counts to the server-wide tally when they change - which is
  // on a MonitoredItem create, modify, delete or close, not on the samples that also land here.
  // A close that runs after the server is destroyed finds no router to report to
  // (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01).
  if (auto router = mRegistry.lock())
  {
    SubscriptionRouter::SamplingIntervalCounts counts;
    for (const auto& entry : intervals)
      counts[entry.samplingInterval] = entry.monitoredItemCount;
    if (counts != mReportedSamplingIntervals)
    {
      router->update_sampling_intervals(mReportedSamplingIntervals, counts);
      mReportedSamplingIntervals = std::move(counts);
    }
  }

  const std::lock_guard lock(mInfoMutex);
  mCachedInfo.id = mId;
  mCachedInfo.priority = mPriority;
  mCachedInfo.publishingInterval = mPublishingInterval;
  mCachedInfo.monitoredItemCount = numeric_cast<uint32_t>(mMonitoredItems.size());
  mCachedInfo.hasNotifications = notifications_available();
  mCachedInfo.readyToPublish = mReadyToPublish;
  mCachedInfo.peekSequenceNumber = peek_sequence_number();
  mCachedInfo.maxKeepAliveCount = mMaxKeepAliveCount;
  mCachedInfo.maxLifetimeCount = mLifetimeCount;
  mCachedInfo.maxNotificationsPerPublish = mMaxNotificationsPerPublish;
  mCachedInfo.publishingEnabled = mPublishingEnabled;
  mCachedInfo.currentKeepAliveCount = mKeepAliveCounter;
  mCachedInfo.currentLifetimeCount = mLifetimeCounter;
  mCachedInfo.disabledMonitoredItemCount = disabledCount;
  mCachedInfo.monitoringQueueOverflowCount = dataOverflow;
  mCachedInfo.eventQueueOverflowCount = eventOverflow;
  mCachedInfo.samplingIntervals = std::move(intervals);
}

// --- Diagnostic counter recording (mutex-guarded; safe from any strand) ---

void Subscription::record_modified()
{
  const std::lock_guard lock(mInfoMutex);
  ++mCachedInfo.modifyCount;
}

void Subscription::record_publishing_mode(bool enabled)
{
  const std::lock_guard lock(mInfoMutex);
  if (enabled)
    ++mCachedInfo.enableCount;
  else
    ++mCachedInfo.disableCount;
}

void Subscription::record_publish_serviced()
{
  const std::lock_guard lock(mInfoMutex);
  ++mCachedInfo.publishRequestCount;
}

void Subscription::record_notifications(uint32_t dataChangeCount, uint32_t eventCount)
{
  const std::lock_guard lock(mInfoMutex);
  mCachedInfo.dataChangeNotificationsCount += dataChangeCount;
  mCachedInfo.eventNotificationsCount += eventCount;
  mCachedInfo.notificationsCount += (dataChangeCount + eventCount);
}

void Subscription::record_late_publish()
{
  const std::lock_guard lock(mInfoMutex);
  ++mCachedInfo.latePublishRequestCount;
}

void Subscription::record_republish_request()
{
  const std::lock_guard lock(mInfoMutex);
  ++mCachedInfo.republishRequestCount;
  ++mCachedInfo.republishMessageRequestCount;
}

void Subscription::record_republish_message()
{
  const std::lock_guard lock(mInfoMutex);
  ++mCachedInfo.republishMessageCount;
}

void Subscription::record_transfer_request()
{
  const std::lock_guard lock(mInfoMutex);
  ++mCachedInfo.transferRequestCount;
}

void Subscription::record_transferred(bool sameClient)
{
  const std::lock_guard lock(mInfoMutex);
  if (sameClient)
    ++mCachedInfo.transferredToSameClientCount;
  else
    ++mCachedInfo.transferredToAltClientCount;
}

void Subscription::record_discarded_message()
{
  const std::lock_guard lock(mInfoMutex);
  ++mCachedInfo.discardedMessageCount;
}

void Subscription::set_unacknowledged_message_count(uint32_t count)
{
  const std::lock_guard lock(mInfoMutex);
  mCachedInfo.unacknowledgedMessageCount = count;
}

void Subscription::enter_late_state()
{
  if (mPublishingState != PublishingState::Late)
    record_late_publish();
  mPublishingState = PublishingState::Late;
}

// --- Fire-and-forget async methods ---

void Subscription::modify_async(Duration publishingInterval, uint32_t lifetimeCount,
  uint32_t maxKeepAliveCount, uint32_t maxNotificationsPerPublish, uint8_t priority)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [publishingInterval, lifetimeCount, maxKeepAliveCount, maxNotificationsPerPublish, priority](
      Subscription& self)
    {
      self.modify(publishingInterval, lifetimeCount, maxKeepAliveCount, maxNotificationsPerPublish, priority);
    })();
}

void Subscription::set_publishing_mode_async(bool enabled)
{
  ua::async::post_borrowing(
    this, mStrand, mLogger, [enabled](Subscription& self) { self.set_publishing_mode(enabled); })();
}

void Subscription::on_service_call_async()
{
  ua::async::post_borrowing(this, mStrand, mLogger, [](Subscription& self) { self.on_service_call(); })();
}

void Subscription::close_async()
{
  ua::async::post_borrowing(this, mStrand, mLogger, [](Subscription& self) { self.close(); })();
}

void Subscription::close_async(std::function<void()> callback)
{
  // Completion-owning: the user callback fires exactly once, including when the Subscription is already
  // gone by the time the strand turn runs. The void callback is adapted to the completion overload's
  // single-argument delivery channel through a VoidResult carrier that the callback simply ignores.
  ua::async::post_borrowing(
    this,
    mStrand,
    mLogger,
    [callback = std::move(callback)](VoidResult) mutable
    {
      if (callback)
        callback();
    },
    VoidResult{},
    [](Subscription& self, auto completion)
    {
      self.close();
      completion(VoidResult{});
    })();
}

void Subscription::rewire_callbacks_async(
  NotifyReady onReady, NotifyExpired onExpired, std::optional<uint32_t> maxResponseMessageSize)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [onReady = std::move(onReady), onExpired = std::move(onExpired), maxResponseMessageSize](
      Subscription& self) mutable
    {
      self.rewire_callbacks(std::move(onReady), std::move(onExpired));
      if (maxResponseMessageSize)
        self.mMaxResponseMessageSize = *maxResponseMessageSize;
    })();
}

void Subscription::resend_initial_values_async(std::function<void(VoidResult)> callback)
{
  auto completion = ua::detail::make_fire_once<VoidResult>(std::move(callback));
  auto weak = weak_from_this();
  try
  {
    reauthorize_all_async(
      [weak, completion](VoidResult result) mutable
      {
        auto self = weak.lock();
        if (!self)
        {
          completion(VoidResult{StatusCode{Status::BadSubscriptionIdInvalid}});
          return;
        }
        if (result.is_bad())
        {
          if (const auto& detail = result.shared_detail())
          {
            self->mLogger.error({{"status", to_string(result.status_code())},
                                  {"error_code", detail->code},
                                  {"summary", detail->summary}},
              "ResendData authorization refresh failed");
          }
          else
          {
            self->mLogger.error(
              {{"status", to_string(result.status_code())}}, "ResendData authorization refresh failed");
          }
          completion(std::move(result));
          return;
        }
        self->resend_initial_values();
        completion(VoidResult{});
      });
  }
  catch (...)
  {
    completion(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void Subscription::reauthorize_notification_async(NotificationMessage message,
  std::vector<RetainedEventProjection> eventProjections, std::vector<RetainedDataProjection> dataProjections,
  ReauthorizeNotificationCallback callback)
{
  auto completion = ua::detail::make_fire_once<Result<NotificationMessage>>(std::move(callback));
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completion),
    Result<NotificationMessage>{StatusCode{Status::BadSubscriptionIdInvalid}},
    [message = std::move(message),
      eventProjections = std::move(eventProjections),
      dataProjections = std::move(dataProjections)](
      Subscription& self, ReauthorizeNotificationCallback done) mutable
    {
      self.start_republish_projection(
        std::move(message), std::move(eventProjections), std::move(dataProjections), std::move(done));
    })();
}

// =============================================================================================
// Re-authorizing one retained notification
// =============================================================================================

/// Walks one retained notification's subjects: resolve them, authorize them, project the result.
///
/// An operation rather than a member task, because Republish is a per-request entry point and a
/// Subscription may have several in flight. It holds the Subscription WEAKLY and re-locks it at every
/// resumption: a subscription really may close while a namespace is answering, and the walk has
/// nothing useful to do against a closed one. @see ua::async::SelfOwningOperation
class Subscription::RepublishProjectionOperation final
  : public ua::async::SelfOwningOperation<Subscription::RepublishProjectionOperation>
{
public:
  RepublishProjectionOperation(std::weak_ptr<Subscription> subscription,
    boost::asio::strand<boost::asio::any_io_executor> strand, Logger logger, RepublishProjection work,
    ReauthorizeNotificationCallback completion)
    : SelfOwningOperation(std::move(strand), std::move(logger)), mSubscription(std::move(subscription)),
      mWork(std::move(work)), mCompletion(std::move(completion))
  {}

  static void start(const std::shared_ptr<Subscription>& subscription, RepublishProjection work,
    ReauthorizeNotificationCallback completion)
  {
    launch(std::make_shared<RepublishProjectionOperation>(
      subscription, subscription->mStrand, subscription->mLogger, std::move(work), std::move(completion)));
  }

private:
  friend class ua::async::SelfOwningOperation<Subscription::RepublishProjectionOperation>;

  void answer(Result<NotificationMessage> result)
  {
    auto completion = std::move(mCompletion);
    mCompletion = nullptr;
    if (completion)
    {
      completion(std::move(result));
    }
  }

  void fail_to_start(StatusCode status)
  {
    answer(Result<NotificationMessage>{status});
  }

  ua::async::Task<> run()
  {
    try
    {
      co_await walk();
    }
    catch (const ua::async::Abandoned& abandoned)
    {
      // ANSWERED, not rethrown: this is a root task and its caller is owed exactly one answer.
      answer(Result<NotificationMessage>{abandoned.status_code()});
    }
    catch (...)
    {
      ua::async::guarded(mLogger,
        [this]
        { answer(Result<NotificationMessage>{ua::exception_to_status_code(std::current_exception())}); })();
    }
  }

  ua::async::Task<> walk()
  {
    std::vector<NodeId> subjects;
    subjects.reserve(mWork.plan.size());
    for (const auto& subject : mWork.plan)
    {
      subjects.push_back(subject.nodeId);
    }

    auto batch = co_await await_step<BatchResult<NodeAccessorResult>>(
      [this, &subjects](auto completion)
      {
        if (auto addressSpace = mWork.addressSpace.lock())
        {
          addressSpace->find_nodes_async(subjects, std::move(completion));
          return;
        }
        BatchResult<NodeAccessorResult> gone;
        gone.batchStatus = VoidResult{ua::detail::address_space_gone("Subscription")};
        completion(std::move(gone));
      });

    {
      auto subscription = mSubscription.lock();
      if (!subscription || subscription->mClosed)
      {
        answer(Result<NotificationMessage>{StatusCode{Status::BadSubscriptionIdInvalid}});
        co_return;
      }
    }

    if (batch.batchStatus.is_bad())
    {
      answer(Result<NotificationMessage>{batch.batchStatus.status_code(), batch.batchStatus.shared_detail()});
      co_return;
    }
    if (batch.items.size() != mWork.plan.size())
    {
      answer(Result<NotificationMessage>{StatusCode{Status::BadUnexpectedError,
        ErrorDetail::build("RepublishSubjectResolutionCardinalityMismatch",
          "Retained notification subject resolution returned the wrong number of items",
          "Subscription")
          .context(ContextKeys::expected, std::to_string(mWork.plan.size()))
          .context(ContextKeys::actual, std::to_string(batch.items.size()))}});
      co_return;
    }

    mWork.verdicts.resize(mWork.plan.size());
    for (size_t index = 0; index < mWork.plan.size(); ++index)
    {
      const auto& subject = mWork.plan[index];
      auto& resolved = batch.items[index];
      // An answer that is not Good holds no Node to authorize: an Uncertain one denies as a Bad one does
      // (DL-45).
      if (!resolved.is_good())
      {
        mWork.verdicts[index] = AccessControl::Verdict{.subject = subject.nodeId,
          .operation = subject.operation,
          .permitted = false,
          .cause = event_subject_resolution_denied(subject, resolved.status_code())};
        continue;
      }
      mWork.resolvedPlanIndices.push_back(index);
      mWork.resolvedItems.push_back(AccessControl::Item{std::move(resolved).value(), subject.operation});
    }

    if (!mWork.resolvedItems.empty())
    {
      auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this](auto completion)
        { mWork.accessControl.authorize_async(RequestInfo{}, mWork.resolvedItems, std::move(completion)); });

      {
        auto subscription = mSubscription.lock();
        if (!subscription || subscription->mClosed)
        {
          answer(Result<NotificationMessage>{StatusCode{Status::BadSubscriptionIdInvalid}});
          co_return;
        }
      }

      if (verdicts.size() != mWork.resolvedPlanIndices.size())
      {
        answer(Result<NotificationMessage>{StatusCode{Status::BadUnexpectedError,
          ErrorDetail::build("RepublishAuthorizationCardinalityMismatch",
            "Retained notification authorization returned the wrong number of verdicts",
            "Subscription")
            .context(ContextKeys::expected, std::to_string(mWork.resolvedPlanIndices.size()))
            .context(ContextKeys::actual, std::to_string(verdicts.size()))}});
        co_return;
      }
      for (size_t index = 0; index < verdicts.size(); ++index)
      {
        const size_t planIndex = mWork.resolvedPlanIndices[index];
        verdicts[index].subject = mWork.plan[planIndex].nodeId;
        verdicts[index].operation = mWork.plan[planIndex].operation;
        mWork.verdicts[planIndex] = std::move(verdicts[index]);
      }
    }

    auto subscription = mSubscription.lock();
    if (!subscription)
    {
      answer(Result<NotificationMessage>{StatusCode{Status::BadSubscriptionIdInvalid}});
      co_return;
    }
    auto completion = std::move(mCompletion);
    mCompletion = nullptr;
    subscription->finish_republish_projection(mWork, std::move(completion));
  }

  std::weak_ptr<Subscription> mSubscription;
  RepublishProjection mWork;
  ReauthorizeNotificationCallback mCompletion;
};

void Subscription::start_republish_projection(NotificationMessage message,
  std::vector<RetainedEventProjection> eventProjections, std::vector<RetainedDataProjection> dataProjections,
  ReauthorizeNotificationCallback completion)
{
  if (mClosed)
  {
    completion(Result<NotificationMessage>{StatusCode{Status::BadSubscriptionIdInvalid}});
    return;
  }

  const size_t dataCount = retained_data_count(message);
  const size_t eventCount = retained_event_count(message);
  if (dataCount == 0 && eventCount == 0)
  {
    completion(Result<NotificationMessage>{std::move(message)});
    return;
  }

  auto securityContext = mRecheckSecurityContext.lock();
  auto addressSpace = mRecheckAddressSpace.lock();
  std::optional<SessionAccessControl> accessControl;
  if (securityContext && addressSpace)
    accessControl =
      SessionAccessControl::create(*securityContext, *addressSpace, mAccessControlTimeout, mLogger);

  if (!addressSpace || !accessControl)
  {
    const StatusCode unavailable{Status::BadUserAccessDenied,
      ErrorDetail::build("RepublishAuthorizationContextUnavailable",
        "The retained notification could not be authorized without the current Session identity and address "
        "space",
        "Subscription")};
    for (auto& notification : message.notification_data())
    {
      auto* dataChange = dynamic_cast<DataChangeNotification*>(notification.get());
      if (!dataChange)
        continue;
      for (auto& item : dataChange->monitored_items())
        item.value() = DataValue{unavailable};
    }
    remove_retained_events(message);
    completion(Result<NotificationMessage>{std::move(message)});
    return;
  }

  RepublishProjection work{std::move(message),
    std::move(eventProjections),
    std::move(dataProjections),
    std::move(*addressSpace),
    std::move(*accessControl)};

  const auto appendSubject = [&work](CompiledEventFilter::AuthorizationSubject subject)
  {
    const auto duplicate = std::ranges::find_if(work.plan,
      [&subject](const CompiledEventFilter::AuthorizationSubject& candidate)
      { return candidate.nodeId == subject.nodeId && candidate.operation == subject.operation; });
    if (duplicate == work.plan.end())
      work.plan.push_back(std::move(subject));
  };
  for (const auto& projection : work.dataProjections)
  {
    appendSubject(CompiledEventFilter::AuthorizationSubject{
      projection.subject, AccessControl::attribute_read_operation(projection.attribute)});
  }
  for (const auto& projection : work.eventProjections)
  {
    if (!projection.complete())
      continue;
    appendSubject(CompiledEventFilter::AuthorizationSubject{
      receive_events_source_subject(projection.sourceNode), AccessOperation::ReceiveEvents});
    appendSubject(
      CompiledEventFilter::AuthorizationSubject{projection.eventType, AccessOperation::ReceiveEvents});
    auto filterSubjects = projection.filter->authorization_subjects(
      *projection.userIndependentEvent, projection.declarationModel);
    for (auto& subject : filterSubjects)
      appendSubject(std::move(subject));
  }
  if (work.plan.empty())
  {
    // Nothing to authorize, so nothing to wait for: the projection is decided already.
    finish_republish_projection(work, std::move(completion));
    return;
  }

  // Everything past here needs a namespace and an authorizer to answer, so it becomes an operation of
  // its own - Republish is a per-request entry point, and a Subscription may have several in flight.
  RepublishProjectionOperation::start(shared_from_this(), std::move(work), std::move(completion));
}

void Subscription::finish_republish_projection(
  RepublishProjection& work, ReauthorizeNotificationCallback completion)
{
  if (mClosed)
  {
    completion(Result<NotificationMessage>{StatusCode{Status::BadSubscriptionIdInvalid}});
    return;
  }

  auto securityContext = mRecheckSecurityContext.lock();
  const auto currentIdentity = securityContext ? securityContext->access_identity() : nullptr;
  if (!currentIdentity || currentIdentity->key() != work.accessControl.identity()->key())
  {
    completion(Result<NotificationMessage>{StatusCode{Status::BadUserAccessDenied,
      ErrorDetail::build("RepublishIdentityChanged",
        "The Session identity changed while retained notification authorization was in flight",
        "Subscription")}});
    return;
  }

  const auto verdictFor = [&work](
                            const NodeId& node, AccessOperation operation) -> const AccessControl::Verdict*
  {
    const auto found = std::ranges::find_if(work.verdicts,
      [&](const AccessControl::Verdict& verdict)
      { return verdict.subject == node && verdict.operation == operation; });
    return found == work.verdicts.end() ? nullptr : &*found;
  };
  const auto itemFor = [&work](const NodeId& node, AccessOperation operation) -> const AccessControl::Item*
  {
    const auto found = std::ranges::find_if(work.resolvedItems,
      [&](const AccessControl::Item& item)
      {
        try
        {
          return item.node.get_node_id() == node && item.operation == operation;
        }
        catch (...)
        {
          return false;
        }
      });
    return found == work.resolvedItems.end() ? nullptr : &*found;
  };
  const auto deniedValue = [](std::string code, std::string message, const StatusCode* cause = nullptr)
  {
    auto detail = ErrorDetail::build(std::move(code), std::move(message), "Subscription");
    if (cause && cause->is_bad())
      detail.cause(*cause);
    return DataValue{StatusCode{Status::BadUserAccessDenied, std::move(detail)}};
  };

  size_t dataCursor = 0;
  for (auto& notification : work.message.notification_data())
  {
    auto* dataChange = dynamic_cast<DataChangeNotification*>(notification.get());
    if (!dataChange)
      continue;
    for (auto& retainedItem : dataChange->monitored_items())
    {
      if (dataCursor >= work.dataProjections.size())
      {
        retainedItem.value() = deniedValue("RetainedDataProjectionMissing",
          "The retained data notification has no aligned projection sidecar");
        ++dataCursor;
        continue;
      }
      const auto& projection = work.dataProjections[dataCursor++];
      const auto operation = AccessControl::attribute_read_operation(projection.attribute);
      const auto* verdict = verdictFor(projection.subject, operation);
      const auto* resolved = itemFor(projection.subject, operation);
      if (!projection.userIndependentValue)
      {
        retainedItem.value() = deniedValue("RetainedDataInputMissing",
          "The retained data notification has no user-independent projection input");
      }
      else if (!verdict || !verdict->permitted)
      {
        const StatusCode* cause = verdict ? &verdict->cause : nullptr;
        retainedItem.value() = deniedValue("RetainedDataReadDenied",
          "The receiving identity may not read the retained data notification",
          cause);
      }
      else if (!resolved)
      {
        retainedItem.value() = deniedValue(
          "RetainedDataSubjectMissing", "The retained data subject was not resolved for projection");
      }
      else
      {
        // The values are projected afresh for the receiving identity, but the timestamps are those the
        // notification was published with: a Republish resends that message, and the
        // CreateMonitoredItems timestampsToReturn already decided which timestamps it carries.
        // Against the retained subject, which a deletion since the original publish does not change.
        auto reprojected = work.accessControl.make_client_attribute_value(projection.subject,
          resolved->node,
          projection.attribute,
          *projection.userIndependentValue,
          *verdict);
        // A value the server produces is narrowed again, as it was when published
        // (COMP-SVR-NAMESPACE-CALLS-15 rule 4); the range is empty for any other value, which was retained
        // narrowed.
        index_range_utils::apply_to_value(reprojected, projection.indexRange);
        const auto& published = retainedItem.value();
        reprojected.source_timestamp() = published.source_timestamp();
        reprojected.source_pico_seconds() = published.source_pico_seconds();
        reprojected.server_timestamp() = published.server_timestamp();
        reprojected.server_pico_seconds() = published.server_pico_seconds();
        keep_published_info_bits(reprojected, published);
        retainedItem.value() = std::move(reprojected);
      }
    }
  }

  std::vector<bool> eventPermitted(retained_event_count(work.message), false);
  size_t eventCursor = 0;
  for (auto& notification : work.message.notification_data())
  {
    auto* eventList = dynamic_cast<EventNotificationList*>(notification.get());
    if (!eventList)
      continue;
    for (auto& retainedEvent : eventList->events())
    {
      if (eventCursor >= work.eventProjections.size())
      {
        ++eventCursor;
        continue;
      }
      const auto& projection = work.eventProjections[eventCursor];
      if (!projection.complete())
      {
        ++eventCursor;
        continue;
      }
      const auto* sourceVerdict =
        verdictFor(receive_events_source_subject(projection.sourceNode), AccessOperation::ReceiveEvents);
      const auto* typeVerdict = verdictFor(projection.eventType, AccessOperation::ReceiveEvents);
      if (!sourceVerdict || !sourceVerdict->permitted || !typeVerdict || !typeVerdict->permitted ||
          !projection.filter->evaluate_authorized(
            *projection.userIndependentEvent, projection.declarationModel, work.verdicts))
      {
        ++eventCursor;
        continue;
      }

      retainedEvent = projection.filter->project_authorized(*projection.userIndependentEvent,
        projection.clientHandle,
        projection.declarationModel,
        work.accessControl,
        work.resolvedItems,
        work.verdicts,
        mMaxResponseMessageSize);
      eventPermitted[eventCursor] = true;
      ++eventCursor;
    }
  }
  filter_retained_events(work.message, eventPermitted);
  completion(Result<NotificationMessage>{std::move(work.message)});
}

void Subscription::update_registry_owner_async(std::weak_ptr<Session> newOwner)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [newOwner = std::move(newOwner)](Subscription& self) mutable
    { self.update_registry_owner(std::move(newOwner)); })();
}

void Subscription::set_publish_req_queued_async(bool queued)
{
  ua::async::post_borrowing(
    this, mStrand, mLogger, [queued](Subscription& self) { self.set_publish_req_queued(queued); })();
}

// --- Callback async methods ---

void Subscription::fulfill_publish_async(
  uint32_t availablePublishCount, bool publishReqQueued, FulfillPublishCallback completionHandler)
{
  // Completion-owning: `callback` fires exactly once. On the gone path it delivers an empty
  // PublishResult vector; on the live path it delivers the fulfilled results.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::vector<PublishResult>{},
    [availablePublishCount, publishReqQueued](Subscription& self, FulfillPublishCallback callback)
    {
      self.set_publish_req_queued(publishReqQueued);
      auto results = self.fulfill_publish(availablePublishCount);
      callback(std::move(results));
    })();
}

void Subscription::create_monitored_items_async(CreateMonitoredItemsRequest request,
  AddressSpace addressSpace, ServerConfig::ServerCapabilities capabilities,
  ServerConfig::SubscriptionLimits subscriptionLimits,
  std::shared_ptr<SessionSecurityContext> securityContext, std::weak_ptr<EventBus> eventBus,
  std::shared_ptr<ServerSummaryCounters> summaryCounters, CreateMonitoredItemsCallback completionHandler,
  std::vector<LocaleId> locales)
{
  // 5.3 synchronous-completion paths: empty items list or all-Phase-1-rejected
  // run start_create -> complete_create inline on the strand turn following this
  // post (no async hop required).
  //
  // Completion-owning: `callback` fires exactly once. The gone-self result is computed here from the
  // request size (all-bad, BadSubscriptionIdInvalid) before the request is moved into the handler; the
  // single-flight gate stays inside the handler because it reads strand-guarded state
  // (mCreateRunning).
  std::vector<MonitoredItemCreateResult> goneResults(request.items_to_create().size());
  for (auto& r : goneResults)
  {
    r.status_code() = StatusCode{Status::BadSubscriptionIdInvalid};
  }
  // The request's timeoutHint counts from here, its arrival at the Subscription.
  const auto arrival = std::chrono::steady_clock::now();

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::move(goneResults),
    [arrival,
      request = std::move(request),
      addressSpace = std::move(addressSpace),
      capabilities = std::move(capabilities),
      subscriptionLimits = std::move(subscriptionLimits),
      securityContext = std::move(securityContext),
      eventBus = std::move(eventBus),
      summaryCounters = std::move(summaryCounters),
      locales = std::move(locales)](Subscription& self, CreateMonitoredItemsCallback callback) mutable
    {
      // Single-flight gate (5.4.1; pin CMI-P): a second CMI arriving while one
      // is in flight is rejected with BadInvalidState.
      if (self.mCreateRunning)
      {
        std::vector<MonitoredItemCreateResult> failed(request.items_to_create().size());
        for (auto& r : failed)
        {
          r.status_code() = StatusCode{Status::BadInvalidState};
        }
        callback(std::move(failed));
        return;
      }

      // CreateMonitoredItems has no partial results, so the request carries no answerBy; it carries the
      // Session's locales (NR-8).
      auto cancelled = std::make_shared<std::atomic_bool>(false);
      const uint32_t timeoutHint = request.request_header().timeout_hint();
      CreateInputs inputs{.request = std::move(request),
        .addressSpace = std::move(addressSpace),
        .accessControl = std::nullopt,
        .capabilities = std::move(capabilities),
        .subscriptionLimits = std::move(subscriptionLimits),
        .securityContext = std::move(securityContext),
        .eventBus = std::move(eventBus),
        .summaryCounters = std::move(summaryCounters),
        .requestInfo =
          service_request_info(arrival, timeoutHint, std::nullopt, cancelled, std::move(locales))};
      if (inputs.securityContext)
      {
        inputs.accessControl = SessionAccessControl::create(
          *inputs.securityContext, inputs.addressSpace, self.mAccessControlTimeout, self.mLogger);
      }

      self.mCreateRunning = true;
      self.mCreateItemCount = inputs.request.items_to_create().size();
      self.mCreateCompletion = std::move(callback);
      self.mCreateCancelled = std::move(cancelled);
      try
      {
        self.start_create(std::move(inputs));
      }
      catch (...)
      {
        // The body contains itself; what is left out here is the frame allocation, which happens
        // after the create has been marked running and would otherwise latch it.
        self.fail_create(ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

void Subscription::delete_monitored_items_async(std::vector<IntegerId> monitoredItemIds,
  AddressSpace addressSpace, std::weak_ptr<EventBus> eventBus,
  std::shared_ptr<ServerSummaryCounters> summaryCounters, DeleteMonitoredItemsCallback completionHandler)
{
  // 5.3 synchronous-completion paths: empty input, only event items, or only
  // invalid IDs have no namespace to call, so the body runs start to finish on
  // the strand turn following this post (no async hop required).
  //
  // Completion-owning: `callback` fires exactly once. The gone-self result (all-bad,
  // BadSubscriptionIdInvalid, sized to the input) is computed here before the ids are moved into the
  // handler; the single-flight gate stays inside the handler (reads the strand-guarded mDeleteRunning).
  std::vector<StatusCode> goneResults(monitoredItemIds.size(), StatusCode{Status::BadSubscriptionIdInvalid});

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::move(goneResults),
    [monitoredItemIds = std::move(monitoredItemIds),
      addressSpace = std::move(addressSpace),
      eventBus = std::move(eventBus),
      summaryCounters = std::move(summaryCounters)](
      Subscription& self, DeleteMonitoredItemsCallback callback) mutable
    {
      // Single-flight gate (5.4.1): a second delete arriving while one is in
      // flight is rejected. The runbook 3.2 Flow 2 did not yet specify this
      // gate; the 4.11b flip adopts the CMI single-flight shape for symmetry.
      if (self.mDeleteRunning)
      {
        std::vector<StatusCode> failed(monitoredItemIds.size(), StatusCode{Status::BadInvalidState});
        callback(std::move(failed));
        return;
      }

      self.mDeleteRunning = true;
      self.mDeleteItemCount = monitoredItemIds.size();
      self.mDeleteCompletion = std::move(callback);
      try
      {
        self.start_delete(std::move(monitoredItemIds),
          std::move(addressSpace),
          std::move(eventBus),
          std::move(summaryCounters));
      }
      catch (...)
      {
        // The body contains itself; what is left out here is the frame allocation, which happens
        // after the delete has been marked running and would otherwise latch it.
        self.fail_delete(ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

void Subscription::modify_monitored_items_async(ModifyMonitoredItemsRequest request,
  AddressSpace addressSpace, ServerConfig::ServerCapabilities capabilities,
  ServerConfig::SubscriptionLimits subscriptionLimits, ModifyMonitoredItemsCallback completionHandler,
  std::vector<LocaleId> locales)
{
  // 5.3 synchronous-completion paths: empty items list or all-invalid IDs
  // run start_modify -> complete_modify inline on the strand turn following
  // this post (no async hop required).
  //
  // Completion-owning: `callback` fires exactly once. The gone-self result (all-bad,
  // BadSubscriptionIdInvalid, sized to the request) is computed here before the request is moved into
  // the handler; the single-flight gate stays inside the handler (reads the strand-guarded mModifyRunning).
  std::vector<MonitoredItemModifyResult> goneResults(request.items_to_modify().size());
  for (auto& r : goneResults)
  {
    r.status_code() = StatusCode{Status::BadSubscriptionIdInvalid};
  }
  // The request's timeoutHint counts from here, its arrival at the Subscription.
  const auto arrival = std::chrono::steady_clock::now();

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::move(goneResults),
    [arrival,
      request = std::move(request),
      addressSpace = std::move(addressSpace),
      capabilities,
      subscriptionLimits,
      locales = std::move(locales)](Subscription& self, ModifyMonitoredItemsCallback callback) mutable
    {
      // Single-flight gate (5.4.1): two concurrent Modifies on the same
      // Subscription are rejected with BadInvalidState (CMI shape symmetry).
      if (self.mModifyRunning)
      {
        std::vector<MonitoredItemModifyResult> failed(request.items_to_modify().size());
        for (auto& r : failed)
        {
          r.status_code() = StatusCode{Status::BadInvalidState};
        }
        callback(std::move(failed));
        return;
      }

      self.mModifyRunning = true;
      self.mModifyItemCount = request.items_to_modify().size();
      self.mModifyCompletion = std::move(callback);
      // ModifyMonitoredItems has no partial results, so the request carries no answerBy; it carries the
      // Session's locales (NR-8).
      auto cancelled = std::make_shared<std::atomic_bool>(false);
      self.mModifyCancelled = cancelled;
      auto requestInfo = service_request_info(
        arrival, request.request_header().timeout_hint(), std::nullopt, cancelled, std::move(locales));
      try
      {
        self.start_modify(std::move(request),
          std::move(addressSpace),
          std::move(capabilities),
          std::move(subscriptionLimits),
          std::move(requestInfo));
      }
      catch (...)
      {
        // The body contains itself; what is left out here is the frame allocation, which happens
        // after the modify has been marked running and would otherwise latch it.
        self.fail_modify(ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

void Subscription::set_monitoring_mode_async(std::vector<IntegerId> monitoredItemIds, MonitoringMode newMode,
  SetMonitoringModeCallback completionHandler)
{
  // Completion-owning: `callback` fires exactly once. The gone path preserves request cardinality so a
  // caller never loses the per-item association when the Subscription expires before its strand turn.
  std::vector<StatusCode> goneResults(monitoredItemIds.size(), StatusCode{Status::BadSubscriptionIdInvalid});
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    std::move(goneResults),
    [monitoredItemIds = std::move(monitoredItemIds), newMode](
      Subscription& self, SetMonitoringModeCallback callback) mutable
    {
      if (self.mClosed)
      {
        std::vector<StatusCode> closedResults(
          monitoredItemIds.size(), StatusCode{Status::BadSubscriptionIdInvalid});
        callback(std::move(closedResults));
        return;
      }
      if (self.mSetMonitoringModeRunning)
      {
        std::vector<StatusCode> busyResults(monitoredItemIds.size(), monitoring_mode_change_busy());
        callback(std::move(busyResults));
        return;
      }

      self.mSetMonitoringModeRunning = true;
      self.mSetMonitoringModeItemCount = monitoredItemIds.size();
      self.mSetMonitoringModeCompletion = std::move(callback);
      try
      {
        self.start_set_monitoring_mode(std::move(monitoredItemIds), newMode);
      }
      catch (...)
      {
        // The body contains itself; what is left out here is the frame allocation, which happens
        // after the change has been marked running and would otherwise latch it.
        self.fail_set_monitoring_mode(ua::exception_to_status_code(std::current_exception()));
      }
    })();
}

void Subscription::set_triggering_async(IntegerId triggeringItemId, std::vector<IntegerId> linksToAdd,
  std::vector<IntegerId> linksToRemove, SetTriggeringCallback completionHandler)
{
  // Completion-owning: `callback` fires exactly once; the gone path delivers a default SetTriggeringResult.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    SetTriggeringResult{},
    [triggeringItemId, linksToAdd = std::move(linksToAdd), linksToRemove = std::move(linksToRemove)](
      Subscription& self, SetTriggeringCallback callback) mutable
    {
      auto result = self.set_triggering(triggeringItemId, linksToAdd, linksToRemove);
      callback(std::move(result));
    })();
}

void Subscription::get_monitored_item_handles_async(GetMonitoredItemHandlesCallback completionHandler)
{
  // Completion-owning: `callback` fires exactly once; the gone path delivers empty MonitoredItemHandles.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(completionHandler),
    MonitoredItemHandles{},
    [](Subscription& self, GetMonitoredItemHandlesCallback callback)
    {
      MonitoredItemHandles handles;
      handles.serverHandles.reserve(self.mMonitoredItems.size());
      handles.clientHandles.reserve(self.mMonitoredItems.size());
      for (const auto& [serverHandle, item] : self.mMonitoredItems)
      {
        handles.serverHandles.push_back(serverHandle);
        handles.clientHandles.push_back(numeric_cast<uint32_t>(item->clientHandle));
      }
      callback(std::move(handles));
    })();
}

void Subscription::set_durable_async(
  uint32_t lifetimeInHours, ServerConfig::SubscriptionLimits subscriptionLimits, SetDurableCallback callback)
{
  // Completion-owning: `callback` (StatusCode + revisedHours) fires exactly once, including on dead-self
  // where it delivers (BadSubscriptionIdInvalid, 0). The two-argument callback is carried through the
  // completion overload's single-argument channel as a pair; the handler re-adapts it back to the
  // two-argument shape that set_durable expects.
  ua::async::post_borrowing(
    this,
    mStrand,
    mLogger,
    [callback = std::move(callback)](std::pair<StatusCode, uint32_t> gone) mutable
    { callback(gone.first, gone.second); },
    std::pair<StatusCode, uint32_t>{StatusCode{Status::BadSubscriptionIdInvalid}, 0u},
    [lifetimeInHours, subscriptionLimits = std::move(subscriptionLimits)](
      Subscription& self, auto completion) mutable
    {
      self.set_durable(lifetimeInHours,
        subscriptionLimits,
        [completion = std::move(completion)](StatusCode status, uint32_t revisedHours) mutable
        { completion(std::pair<StatusCode, uint32_t>{status, revisedHours}); });
    })();
}

void Subscription::set_durable(uint32_t lifetimeInHours,
  const ServerConfig::SubscriptionLimits& subscriptionLimits, SetDurableCallback callback)
{
  if (mClosed)
  {
    callback(StatusCode{Status::BadSubscriptionIdInvalid}, 0);
    return;
  }

  // Durable subscriptions can be disabled (memory-bounding gate): refuse honestly rather than
  // silently lifting the per-MonitoredItem queue ceiling.
  if (!subscriptionLimits.durableSubscriptionsEnabled)
  {
    callback(StatusCode{Status::BadServiceUnsupported}, 0);
    return;
  }

  // Part 4 5.13.9: SetSubscriptionDurable may only be called before monitored items are added.
  if (!mMonitoredItems.empty())
  {
    callback(StatusCode{Status::BadInvalidState}, 0);
    return;
  }

  // Revise the requested lifetime: at least 1 hour, capped at the configured server maximum.
  const uint32_t revisedHours = std::clamp<uint32_t>(
    lifetimeInHours == 0 ? 1u : lifetimeInHours, 1u, subscriptionLimits.maxDurableSubscriptionLifetimeHours);
  mDurable = true;
  mDurableLifetimeHours = revisedHours;

  // Recompute the lifetime count from the revised hours so the subscription survives the durable
  // window. Lifetime count = publishing cycles before expiry = lifetimeMs / publishingInterval.
  const double intervalMs = mPublishingInterval > 0.0 ? mPublishingInterval : 1.0;
  const double cycles = (static_cast<double>(revisedHours) * 3600.0 * 1000.0) / intervalMs;
  const uint32_t lifetimeFromHours = cycles >= static_cast<double>(std::numeric_limits<uint32_t>::max())
                                       ? std::numeric_limits<uint32_t>::max()
                                       : static_cast<uint32_t>(cycles);
  // Preserve the Part 4 invariant lifetimeCount >= 3 x maxKeepAliveCount.
  const uint32_t minLifetime = mMaxKeepAliveCount > 0 ? 3u * mMaxKeepAliveCount : 1u;
  mLifetimeCount = std::max(lifetimeFromHours, minLifetime);
  mLifetimeCounter = mLifetimeCount;

  update_info();
  callback(StatusCode{Status::Good}, revisedHours);
}

// --- Periodic per-MonitoredItem authorization re-evaluation (Part 4 5.12.2.1) ---

void Subscription::configure_access_recheck(std::chrono::milliseconds interval,
  std::shared_ptr<SessionSecurityContext> securityContext, WeakAddressSpace addressSpace,
  std::weak_ptr<EventBus> eventBus)
{
  // At once, not on the strand: the next sampling tick reads for this Session's caller (NR-49 rule 3).
  mSampleSink->set_security_context(securityContext);
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [interval,
      securityContext = std::move(securityContext),
      addressSpace = std::move(addressSpace),
      eventBus = std::move(eventBus)](Subscription& self) mutable
    {
      if (self.mClosed)
      {
        return;
      }
      self.mAccessRecheckInterval = interval;
      self.mRecheckSecurityContext = securityContext;
      self.mRecheckAddressSpace = std::move(addressSpace);
      self.mRecheckEventBus = std::move(eventBus);
      for (auto& [id, item] : self.mMonitoredItems)
      {
        (void)id;
        item->accessSecurityContext = securityContext;
        item->accessAddressSpace = self.mRecheckAddressSpace;
      }
      self.replay_orphaned_samples();
      self.arm_access_recheck_timer();
    })();
}

void Subscription::reauthorize_all_async(std::function<void(VoidResult)> callback)
{
  auto guardedCompletion = ua::detail::make_fire_once<VoidResult>(std::move(callback));
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(guardedCompletion),
    VoidResult{StatusCode{Status::BadSubscriptionIdInvalid}},
    [](Subscription& self, std::function<void(VoidResult)> completion) mutable
    {
      try
      {
        self.start_mandatory_access_recheck(completion);
      }
      catch (...)
      {
        completion(VoidResult{ua::exception_to_status_code(std::current_exception())});
      }
    })();
}

void Subscription::reauthorize_after_transfer_async(std::function<void(VoidResult)> callback)
{
  auto guardedCompletion = ua::detail::make_fire_once<VoidResult>(std::move(callback));
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(guardedCompletion),
    VoidResult{StatusCode{Status::BadSubscriptionIdInvalid}},
    [](Subscription& self, std::function<void(VoidResult)> completion) mutable
    {
      // The recheck answers on this strand, so the flag is restored there, before the caller hears.
      self.mReprojectUnchangedOnRecheck = false;
      auto restore = [weak = self.weak_from_this(), completion](VoidResult result) mutable
      {
        if (auto subscription = weak.lock())
          subscription->mReprojectUnchangedOnRecheck = true;
        completion(std::move(result));
      };
      try
      {
        self.start_mandatory_access_recheck(restore);
      }
      catch (...)
      {
        restore(VoidResult{ua::exception_to_status_code(std::current_exception())});
      }
    })();
}

void Subscription::arm_access_recheck_timer()
{
  // Strand-confined. Idempotent: armed once when the interval is positive. A tick is a no-op while the
  // subscription holds no items, so arming eagerly at creation costs nothing.
  if (mClosed || mAccessRecheckArmed || mAccessRecheckInterval <= std::chrono::milliseconds{0})
  {
    return;
  }
  mAccessRecheckArmed = true;
  mAccessRecheckTimer = Timer::schedule_every(mStrand,
    mAccessRecheckInterval,
    [weak = weak_from_this()](boost::system::error_code ec)
    {
      if (ec)
      {
        return;  // Timer was cancelled.
      }
      if (auto self = weak.lock())
      {
        self->run_access_recheck(nullptr);
      }
    });
}

void Subscription::run_access_recheck(std::function<void()> onComplete)
{
  auto finishEarly = [&onComplete]
  {
    if (onComplete)
      onComplete();
  };

  if (mClosed || mAccessRecheckRunning || mCreateRunning || mModifyRunning || mDeleteRunning ||
      mSetMonitoringModeRunning)
  {
    finishEarly();
    return;
  }
  if (mMonitoredItems.empty())
  {
    finishEarly();
    return;
  }
  auto securityContext = mRecheckSecurityContext.lock();
  if (!securityContext)
  {
    apply_periodic_recheck_failure_to_all(StatusCode{Status::BadUserAccessDenied,
      ErrorDetail::build("PeriodicAccessRecheckSecurityContextUnavailable",
        "The Session security context is unavailable during periodic MonitoredItem authorization",
        "Subscription")
        .cause(StatusCode{Status::BadInvalidState,
          ErrorDetail::build("SessionSecurityContextExpired",
            "The configured Session security context no longer exists",
            "Subscription")})});
    finishEarly();
    return;
  }
  auto addressSpace = mRecheckAddressSpace.lock();
  if (!addressSpace)
  {
    apply_periodic_recheck_failure_to_all(StatusCode{Status::BadUserAccessDenied,
      ErrorDetail::build("PeriodicAccessRecheckAddressSpaceUnavailable",
        "The AddressSpace is unavailable during periodic MonitoredItem authorization",
        "Subscription")
        .cause(StatusCode{Status::BadInvalidState,
          ErrorDetail::build(
            "AddressSpaceExpired", "The configured AddressSpace no longer exists", "Subscription")})});
    finishEarly();
    return;
  }

  AccessRecheckInputs recheckInputs{std::move(*addressSpace)};
  auto accessControl = SessionAccessControl::create_result(
    *securityContext, recheckInputs.addressSpace, mAccessControlTimeout, mLogger);
  if (!accessControl.is_good())
  {
    apply_periodic_recheck_failure_to_all(StatusCode{Status::BadUserAccessDenied,
      ErrorDetail::build("PeriodicAccessRecheckIdentityUnavailable",
        "The current access identity is unavailable during periodic MonitoredItem authorization",
        "Subscription")
        .cause(accessControl.status_code())});
    finishEarly();
    return;
  }
  recheckInputs.accessControl = std::move(accessControl).value();
  recheckInputs.eventBus = mRecheckEventBus;

  std::vector<IntegerId> itemIds;
  itemIds.reserve(mMonitoredItems.size());
  for (const auto& [miId, item] : mMonitoredItems)
    itemIds.push_back(miId);

  mAccessRecheckRunning = true;
  mAccessRecheckMandatory = false;
  mAccessRecheckCompletion = [onComplete = std::move(onComplete)](VoidResult) mutable
  {
    if (onComplete)
      onComplete();
  };
  start_access_recheck_cycle(std::move(recheckInputs), std::move(itemIds), false);
}

void Subscription::start_mandatory_access_recheck(std::function<void(VoidResult)> callback)
{
  if (mClosed)
  {
    callback(VoidResult{StatusCode{Status::BadSubscriptionIdInvalid}});
    return;
  }
  restart_active_event_delivery_for_identity_change();
  if (mAccessRecheckRunning || mCreateRunning || mModifyRunning || mDeleteRunning ||
      mSetMonitoringModeRunning)
  {
    callback(VoidResult{StatusCode{Status::BadServerTooBusy,
      make_error_detail("ReauthorizationBusy",
        "Subscription cannot begin mandatory reauthorization while another item flow is active",
        "Subscription")}});
    return;
  }
  if (mMonitoredItems.empty())
  {
    callback(VoidResult{});
    return;
  }
  auto securityContext = mRecheckSecurityContext.lock();
  if (!securityContext)
  {
    callback(VoidResult{StatusCode{Status::BadInternalError,
      make_error_detail("SessionSecurityContextExpired",
        "Session security context expired during mandatory MonitoredItem reauthorization",
        "Subscription")}});
    return;
  }
  auto addressSpace = mRecheckAddressSpace.lock();
  if (!addressSpace)
  {
    callback(VoidResult{StatusCode{Status::BadInternalError,
      make_error_detail("AddressSpaceExpired",
        "AddressSpace expired during mandatory MonitoredItem reauthorization",
        "Subscription")}});
    return;
  }

  AccessRecheckInputs recheckInputs{std::move(*addressSpace)};
  auto accessControl = SessionAccessControl::create_result(
    *securityContext, recheckInputs.addressSpace, mAccessControlTimeout, mLogger);
  if (!accessControl.is_good())
  {
    callback(VoidResult{accessControl.status_code(), accessControl.shared_detail()});
    return;
  }
  recheckInputs.accessControl = std::move(accessControl).value();
  recheckInputs.eventBus = mRecheckEventBus;

  std::vector<IntegerId> itemIds;
  itemIds.reserve(mMonitoredItems.size());
  for (const auto& [miId, item] : mMonitoredItems)
    itemIds.push_back(miId);

  mAccessRecheckRunning = true;
  mAccessRecheckMandatory = true;
  mAccessRecheckCompletion = std::move(callback);
  start_access_recheck_cycle(std::move(recheckInputs), std::move(itemIds), true);
}

/// One re-evaluation cycle: one lookup and one authorization for the whole snapshot, then the verdicts
/// applied in snapshot order.
///
/// The snapshot of item ids is taken before the walk starts and every item is looked up again by id
/// at each step, because a concurrent delete is ordinary rather than exceptional. `mAccessRecheckRunning`
/// is asked at every resumption for the same reason the handlers asked whether the cycle was still
/// there: closing the subscription, or a mandatory cycle failed from outside, ends the cycle and the
/// body must notice rather than carry on against state that has been answered for.
void Subscription::start_access_recheck_cycle(
  AccessRecheckInputs inputs, std::vector<IntegerId> itemIds, bool mandatory)
{
  // A task is EAGER: the body runs to its first suspension before this returns, and a cycle whose
  // every item has been deleted finishes there and then - firing its completion, which may start the
  // NEXT cycle before this one has been stored. Storing ours unconditionally would then overwrite a
  // running frame with a finished one, and the new cycle would vanish leaving the single-flight gate
  // closed for ever. The generation says whether the slot is still ours to fill.
  const uint64_t generation = ++mAccessRecheckGeneration;
  auto cycle = run_access_recheck_cycle(std::move(inputs), std::move(itemIds), mandatory);
  if (mAccessRecheckGeneration == generation)
  {
    mAccessRecheckTask = std::move(cycle);
  }
}

ua::async::Task<> Subscription::run_access_recheck_cycle(
  AccessRecheckInputs inputs, std::vector<IntegerId> itemIds, bool mandatory)
{
  // A root task: nobody awaits this, so an exception that escaped would be stored in a promise nobody
  // reads, and the cycle would never end. That matters more here than anywhere else in this file,
  // because `mAccessRecheckRunning` is the gate every item flow tests: a latched cycle blocks
  // CreateMonitoredItems, Modify, Delete and SetMonitoringMode for the life of the subscription, and
  // leaves a mandatory caller waiting for ever.
  try
  {
    co_await walk_access_recheck_cycle(inputs, itemIds, mandatory);
  }
  catch (const ua::async::Abandoned&)
  {
    // Withdrawn: whoever withdrew it ended the cycle and answered its caller.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        if (mAccessRecheckRunning)
        {
          finish_access_recheck(VoidResult{ua::exception_to_status_code(std::current_exception())});
        }
      })();
  }
  co_return;
}

ua::async::Task<> Subscription::walk_access_recheck_cycle(
  AccessRecheckInputs& inputs, const std::vector<IntegerId>& itemIds, bool mandatory)
{
  // Every item's Node is looked up in ONE call and every item found is authorized in ONE call, so each
  // namespace is asked once per step for all of this Subscription's items it holds, whatever their number
  // (NR-23). The verdicts are then applied in snapshot order, as a walk of one item at a time applied them:
  // a periodic cycle denies an item whose lookup or authorization failed and goes on; a mandatory one ends
  // at the first such item, the items before it applied.
  std::vector<RecheckSubject> subjects;
  std::vector<NodeId> nodeIds;
  subjects.reserve(itemIds.size());
  nodeIds.reserve(itemIds.size());
  for (const IntegerId monitoredItemId : itemIds)
  {
    // Items deleted since the snapshot was taken are not looked up.
    if (const auto* item = find_monitored_item(monitoredItemId))
    {
      subjects.emplace_back().monitoredItemId = monitoredItemId;
      nodeIds.push_back(item->itemToMonitor.node_id());
    }
  }

  if (!subjects.empty())
  {
    try
    {
      auto found = co_await await_step<BatchResult<NodeAccessorResult>>([&inputs, &nodeIds](auto completion)
        { inputs.addressSpace.find_nodes_async(nodeIds, std::move(completion)); });
      // One answer per NodeId, taken by position: a failed batch, or an answer of another length, is every
      // item's failure.
      if (found.batchStatus.is_good() && found.items.size() == subjects.size())
      {
        for (size_t position = 0; position < subjects.size(); ++position)
        {
          subjects[position].found = std::move(found.items[position]);
        }
      }
      else
      {
        const StatusCode batchFailure =
          found.batchStatus.is_bad() ? found.batchStatus.status_code()
                                     : recheck_lookup_count_mismatch(subjects.size(), found.items.size());
        for (auto& subject : subjects)
        {
          subject.found = NodeAccessorResult{batchFailure};
        }
      }
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      for (auto& subject : subjects)
      {
        subject.lookupThrew = failure;
      }
    }
  }

  if (!mAccessRecheckRunning)
  {
    co_return;
  }

  // Every item found and still held is authorized, in snapshot order, so that each item the walk below
  // applies has its own verdict.
  std::vector<size_t> decided;
  std::vector<AccessControl::Item> authorizationItems;
  decided.reserve(subjects.size());
  authorizationItems.reserve(subjects.size());
  for (size_t position = 0; position < subjects.size(); ++position)
  {
    const auto& subject = subjects[position];
    const auto* item = find_monitored_item(subject.monitoredItemId);
    if (!item || subject.lookupThrew || !subject.found.is_good())
    {
      continue;
    }
    decided.push_back(position);
    authorizationItems.push_back(
      AccessControl::Item{.node = subject.found.value(), .operation = monitored_item_operation(*item)});
  }

  if (!authorizationItems.empty() && inputs.accessControl)
  {
    try
    {
      auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
        [&inputs, &authorizationItems](auto completion)
        { inputs.accessControl->authorize_async(RequestInfo{}, authorizationItems, std::move(completion)); });
      // One verdict per item, taken by position. An answer of another length is trusted for none of them:
      // `first_verdict_or_denied` of nothing denies.
      for (size_t k = 0; k < decided.size(); ++k)
      {
        std::vector<AccessControl::Verdict> one;
        if (verdicts.size() == decided.size())
        {
          one.push_back(std::move(verdicts[k]));
        }
        subjects[decided[k]].verdict = first_verdict_or_denied(std::move(one));
      }
    }
    catch (const ua::async::Abandoned&)
    {
      co_return;
    }
    catch (...)
    {
      const auto failure = ua::exception_to_status_code(std::current_exception());
      for (const size_t position : decided)
      {
        subjects[position].authorizationThrew = failure;
      }
    }
  }

  for (auto& subject : subjects)
  {
    if (!mAccessRecheckRunning)
    {
      co_return;
    }
    auto* item = find_monitored_item(subject.monitoredItemId);
    if (!item)
    {
      continue;
    }

    if (subject.lookupThrew)
    {
      if (mandatory)
      {
        finish_access_recheck(VoidResult{*subject.lookupThrew});
        co_return;
      }
      apply_periodic_recheck_failure(*item,
        periodic_recheck_denied(item->itemToMonitor.node_id(),
          "PeriodicAccessRecheckLookupThrew",
          "A MonitoredItem node lookup threw during periodic authorization",
          *subject.lookupThrew),
        inputs.accessControl);
      continue;
    }

    if (!subject.found.is_good())
    {
      // An Uncertain answer holds no Node, so it fails the item as a Bad one does.
      const StatusCode lookupFailure =
        subject.found.is_bad()
          ? subject.found.status_code()
          : lookup_answer_uncertain(item->itemToMonitor.node_id(), subject.found.status_code());
      if (mandatory)
      {
        finish_access_recheck(VoidResult{lookupFailure});
        co_return;
      }
      apply_periodic_recheck_failure(*item,
        periodic_recheck_denied(item->itemToMonitor.node_id(),
          "PeriodicAccessRecheckNodeResolutionFailed",
          "A MonitoredItem node could not be resolved during periodic authorization",
          lookupFailure),
        inputs.accessControl);
      continue;
    }

    if (subject.authorizationThrew)
    {
      if (mandatory)
      {
        finish_access_recheck(VoidResult{*subject.authorizationThrew});
        co_return;
      }
      apply_periodic_recheck_failure(*item,
        periodic_recheck_denied(item->itemToMonitor.node_id(),
          "PeriodicAccessRecheckAuthorizationThrew",
          "Periodic MonitoredItem authorization threw after node resolution",
          *subject.authorizationThrew),
        inputs.accessControl);
      continue;
    }

    if (!inputs.accessControl)
    {
      const auto failure = StatusCode{Status::BadUserAccessDenied,
        ErrorDetail::build("PeriodicAccessRecheckIdentityLost",
          "The access identity disappeared before a periodic authorization verdict was applied",
          "Subscription")
          .cause(StatusCode{Status::BadInvalidState,
            ErrorDetail::build("AccessIdentityLost",
              "The periodic authorization flow no longer owns its access identity",
              "Subscription")})};
      if (mandatory)
      {
        finish_access_recheck(VoidResult{failure});
        co_return;
      }
      apply_periodic_recheck_failure(*item, failure, inputs.accessControl);
      continue;
    }

    auto transitionResult = apply_recheck_transition(
      *item, MonitoredAccessSnapshot{inputs.accessControl->identity()->key(), std::move(subject.verdict)});
    if (transitionResult.is_bad())
    {
      if (mandatory)
      {
        finish_access_recheck(std::move(transitionResult));
        co_return;
      }
      apply_periodic_recheck_failure(*item,
        periodic_recheck_denied(item->itemToMonitor.node_id(),
          "PeriodicAccessRecheckTransitionFailed",
          "A periodic MonitoredItem authorization transition could not be applied",
          transitionResult.status_code()),
        inputs.accessControl);
      continue;
    }
  }

  if (mAccessRecheckRunning)
  {
    finish_access_recheck();
  }
  co_return;
}

VoidResult Subscription::apply_recheck_transition(MonitoredItem& item, MonitoredAccessSnapshot snapshot)
{
  const bool wasDenied = item.access_denied();
  const bool denied = !snapshot.verdict.permitted;
  item.accessSnapshot = std::move(snapshot);

  // Samples held while the Subscription had no Session reach the queue only through a snapshot of the
  // identity that now owns it; a denial discards them unseen.
  if (denied)
  {
    item.orphanedSamples.clear();
  }
  else if (replay_orphaned_samples(item))
  {
    mHasNotifications.store(true, std::memory_order_release);
    if (mPublishReqQueued.load(std::memory_order_acquire) && mOnReady)
    {
      mOnReady(mId);
    }
  }

  if (denied == wasDenied)
  {
    // A Boolean latch would return here and retain the old mask. A complete allowed snapshot instead
    // reprojects the latest user-independent value; exact duplicates remain silent and queue order is
    // preserved by ordinary tail insertion.
    if (!denied && mReprojectUnchangedOnRecheck && item.lastUserIndependentValue &&
        snapshot_allows_current_identity(item))
    {
      const bool hadNotifications = item.has_reportable_notifications();
      auto projected =
        project_monitored_value(item, *item.lastUserIndependentValue, mAccessControlTimeout, mLogger);
      const bool enqueued =
        item.enqueue_reprojection_if_changed(std::move(projected), *item.lastUserIndependentValue);
      if (enqueued && !hadNotifications && item.has_reportable_notifications())
      {
        ++mReportableItemCount;
      }
      if (enqueued)
      {
        mHasNotifications.store(true, std::memory_order_release);
        flush_triggered_links(item.id);
        if (mPublishReqQueued.load(std::memory_order_acquire) && mOnReady)
        {
          mOnReady(mId);
        }
      }
    }
    update_info();
    return VoidResult{};
  }

  if (denied)
  {
    // allow -> deny (Part 4 5.12.2.1): stop streaming. The complete-snapshot guard in
    // on_samples_received drops subsequent real samples.
    if (item.isEventItem)
    {
      const bool hadNotifications = item.has_reportable_notifications();
      item.eventQueue.clear();
      item.overflowEventInserted = false;
      item.overflowEventQueued = false;
      item.overflowEventPending = false;
      item.refreshRequired = false;
      item.triggeredReportPending = false;
      discard_pending_event_deliveries(item.id);
      if (item.eventBusHandle != 0)
      {
        if (auto eventBus = mRecheckEventBus.lock())
        {
          eventBus->deregister_event_item(item.eventBusHandle);
        }
        item.eventBusHandle = 0;
      }
      if (hadNotifications && !item.has_reportable_notifications() && mReportableItemCount > 0)
      {
        --mReportableItemCount;
      }
    }
    else
    {
      const bool hadNotifications = item.has_reportable_notifications();
      item.queue.clear();
      item.queuedUserIndependentValues.clear();
      item.lastQueuedValue.reset();
      item.triggeredReportPending = false;
      item.pendingSemanticChange = false;
      item.pendingStructureChange = false;
      DataValue deniedValue;
      deniedValue.status() = item.accessSnapshot->verdict.cause.is_bad()
                               ? item.accessSnapshot->verdict.cause
                               : StatusCode{Status::BadUserAccessDenied};
      deniedValue.source_timestamp() = DateTime::now();
      item.enqueue_initial(std::move(deniedValue));
      if (!hadNotifications && item.has_reportable_notifications())
      {
        ++mReportableItemCount;
      }
      else if (hadNotifications && !item.has_reportable_notifications() && mReportableItemCount > 0)
      {
        --mReportableItemCount;
      }
      if (item.has_reportable_notifications())
      {
        mHasNotifications.store(true, std::memory_order_release);
        if (mPublishReqQueued.load(std::memory_order_acquire) && mOnReady)
        {
          mOnReady(mId);
        }
      }
    }
    mHasNotifications.store(notifications_available(), std::memory_order_release);
  }
  else
  {
    // deny -> allow ("the Server shall start sending data"): clear the gate. Data items resume on the
    // next sampler tick (no prompt re-read - maintainer decision). Event items must re-subscribe.
    if (item.isEventItem)
    {
      auto eventBus = mRecheckEventBus.lock();
      if (!eventBus)
      {
        return VoidResult{StatusCode{Status::BadInternalError,
          make_error_detail("EventBusExpired",
            "EventBus expired while restoring MonitoredItem event permission",
            "Subscription")}};
      }
      register_event_monitored_item(item, *eventBus);
    }
  }
  update_info();
  return VoidResult{};
}

void Subscription::apply_periodic_recheck_failure(
  MonitoredItem& item, StatusCode failure, const std::optional<SessionAccessControl>& cycleAccessControl)
{
  log_periodic_recheck_failure(item.id, failure);
  AccessIdentityKey identity;
  if (item.accessSnapshot)
  {
    identity = item.accessSnapshot->identity;
  }
  if (cycleAccessControl)
  {
    identity = cycleAccessControl->identity()->key();
  }
  auto transition = apply_recheck_transition(item,
    MonitoredAccessSnapshot{identity,
      AccessControl::Verdict{.subject = item.itemToMonitor.node_id(),
        .operation = monitored_item_operation(item),
        .permitted = false,
        .cause = std::move(failure)}});
  if (transition.is_bad())
  {
    log_periodic_recheck_failure(item.id, transition.status_code());
  }
}

void Subscription::apply_periodic_recheck_failure_to_all(StatusCode failure)
{
  for (auto& [monitoredItemId, item] : mMonitoredItems)
  {
    (void)monitoredItemId;
    apply_periodic_recheck_failure(*item, failure);
  }
}

void Subscription::log_periodic_recheck_failure(IntegerId monitoredItemId, const StatusCode& failure) const
{
  if (const auto& detail = failure.shared_detail())
  {
    mLogger.error({{"monitored_item_id", std::to_string(monitoredItemId)},
                    {"status", to_string(failure)},
                    {"detail", to_string(*detail)}},
      "Periodic MonitoredItem authorization failed closed");
  }
  else
  {
    mLogger.error({{"monitored_item_id", std::to_string(monitoredItemId)}, {"status", to_string(failure)}},
      "Periodic MonitoredItem authorization failed closed");
  }
}

void Subscription::finish_access_recheck(VoidResult result)
{
  // Whoever gets here first ends the cycle and answers it once - the body on its way out, `close()`
  // failing a mandatory cycle, or a step that could not go on. Clearing the flag is what an in-flight
  // body reads to discover it was one of the ones that did not get there first.
  auto onComplete = std::move(mAccessRecheckCompletion);
  mAccessRecheckCompletion = nullptr;
  mAccessRecheckRunning = false;
  mAccessRecheckMandatory = false;

  // The finished cycle's frame holds a strong AddressSpace handle and the identity it authorized
  // against, and nothing else would release them until the NEXT cycle overwrote the slot - which for
  // a subscription whose recheck timer has been disarmed is never. Released on a later turn, because
  // this is reached from inside that very frame, and guarded by the generation because a completion
  // below may start the next cycle before that turn runs.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation = mAccessRecheckGeneration](Subscription& self)
    {
      if (self.mAccessRecheckGeneration == generation && !self.mAccessRecheckRunning)
      {
        self.mAccessRecheckTask = {};
      }
    })();

  if (onComplete)
    onComplete(std::move(result));
}

}  // namespace ua::server
