// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the strand-bearing @ref ua::client::detail::EventSubscriberImpl (client
///        design section 8.13): coalescing backbone, composite-filter accumulator, client-side demux, and the
///        event-consumer @ref ua::client::detail::MonitoredItemOwner (resolves the Slice-9
///        `monitor_event` deferral).

#include "ua_event_subscriber_impl.h"

#include "ua_content_filter.h"
#include "ua_element_operand.h"

#include "ua_alarm_condition_tracker_impl.h"
#include "ua_content_filter.h"
#include "ua_content_filter_element.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_objecttype_id.h"
#include "ua_observer_sink.h"
#include "ua_on_strand.h"
#include "ua_status.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace ua::client::detail
{

namespace
{

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;

// The eight BaseEventType mandatory field names (CL-EVT-001), in the canonical composite order (slots 0..7).
constexpr std::array<std::string_view, 8> mandatoryFieldNames{
  "EventId", "EventType", "SourceNode", "SourceName", "Time", "ReceiveTime", "Message", "Severity"};
constexpr std::array<std::string_view, 5> auditMandatoryFieldNames{
  "ActionTimeStamp", "Status", "ServerId", "ClientAuditEntryId", "ClientUserId"};

std::optional<AuditEventCategory> known_audit_category(const ua::NodeId& type)
{
  const auto is = [&type](ua::ObjectTypeId id)
  {
    return type == ua::NodeId{id};
  };
  if (is(ua::ObjectTypeId::AuditEventType))
    return AuditEventCategory::Base;
  if (is(ua::ObjectTypeId::AuditChannelEventType) || is(ua::ObjectTypeId::AuditOpenSecureChannelEventType))
    return AuditEventCategory::Channel;
  if (is(ua::ObjectTypeId::AuditSessionEventType) || is(ua::ObjectTypeId::AuditCreateSessionEventType) ||
      is(ua::ObjectTypeId::AuditActivateSessionEventType) || is(ua::ObjectTypeId::AuditCancelEventType))
    return AuditEventCategory::Session;
  if (is(ua::ObjectTypeId::AuditUpdateMethodEventType) ||
      is(ua::ObjectTypeId::AuditClientUpdateMethodResultEventType))
    return AuditEventCategory::UpdateMethod;
  if (is(ua::ObjectTypeId::AuditNodeManagementEventType) || is(ua::ObjectTypeId::AuditAddNodesEventType) ||
      is(ua::ObjectTypeId::AuditDeleteNodesEventType) || is(ua::ObjectTypeId::AuditAddReferencesEventType) ||
      is(ua::ObjectTypeId::AuditDeleteReferencesEventType) || is(ua::ObjectTypeId::AuditUpdateEventType) ||
      is(ua::ObjectTypeId::AuditWriteUpdateEventType) || is(ua::ObjectTypeId::AuditHistoryUpdateEventType) ||
      is(ua::ObjectTypeId::AuditHistoryEventUpdateEventType) ||
      is(ua::ObjectTypeId::AuditHistoryValueUpdateEventType) ||
      is(ua::ObjectTypeId::AuditHistoryDeleteEventType) ||
      is(ua::ObjectTypeId::AuditHistoryRawModifyDeleteEventType) ||
      is(ua::ObjectTypeId::AuditHistoryAtTimeDeleteEventType) ||
      is(ua::ObjectTypeId::AuditHistoryEventDeleteEventType) ||
      is(ua::ObjectTypeId::AuditHistoryAnnotationUpdateEventType) ||
      is(ua::ObjectTypeId::AuditHistoryConfigurationChangeEventType) ||
      is(ua::ObjectTypeId::AuditHistoryBulkInsertEventType))
    return AuditEventCategory::Update;
  if (is(ua::ObjectTypeId::AuditSecurityEventType) || is(ua::ObjectTypeId::AuditCertificateEventType) ||
      is(ua::ObjectTypeId::AuditCertificateDataMismatchEventType) ||
      is(ua::ObjectTypeId::AuditCertificateExpiredEventType) ||
      is(ua::ObjectTypeId::AuditCertificateInvalidEventType) ||
      is(ua::ObjectTypeId::AuditCertificateUntrustedEventType) ||
      is(ua::ObjectTypeId::AuditCertificateRevokedEventType) ||
      is(ua::ObjectTypeId::AuditCertificateMismatchEventType) ||
      is(ua::ObjectTypeId::AuditUrlMismatchEventType))
    return AuditEventCategory::Security;
  return std::nullopt;
}

ua::SimpleAttributeOperand make_select_clause(std::string_view browseName)
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = ua::NodeId{ua::ObjectTypeId::BaseEventType};
  operand.browse_path().push_back(ua::QualifiedName{0, std::string{browseName}});
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  return operand;
}

// A SelectClause for a field declared on a SPECIFIC event type (not BaseEventType)  -  the browse path
// resolves from @p typeDefinitionId (e.g. GeneralModelChangeEventType's / SemanticChangeEventType's `Changes`
// field).
ua::SimpleAttributeOperand make_typed_select_clause(
  std::string_view browseName, const ua::NodeId& typeDefinitionId)
{
  ua::SimpleAttributeOperand operand;
  operand.type_definition_id() = typeDefinitionId;
  operand.browse_path().push_back(ua::QualifiedName{0, std::string{browseName}});
  operand.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  return operand;
}

std::vector<ua::SimpleAttributeOperand> base_event_mandatory_select_clauses()
{
  std::vector<ua::SimpleAttributeOperand> clauses;
  clauses.reserve(mandatoryFieldNames.size());
  for (const auto name : mandatoryFieldNames)
  {
    clauses.push_back(make_select_clause(name));
  }
  return clauses;
}

// Two SelectClauses are "the same field" iff they name the same (typeDefinition, browsePath, attribute).
bool same_select_clause(const ua::SimpleAttributeOperand& a, const ua::SimpleAttributeOperand& b)
{
  return a == b;
}

// Extract the OfType type ids from a filter's WhereClause (a consumer's "I want events of type X"). An empty
// result means match-all (BaseEventType)  -  the server-side WhereClause is then the placeholder.
std::vector<ua::NodeId> extract_of_types(const ua::EventFilter& filter)
{
  std::vector<ua::NodeId> types;
  for (const auto& element : filter.where_clause().elements())
  {
    if (element.filter_operator() != ua::FilterOperator::OfType)
    {
      continue;
    }
    if (element.filter_operands().size() == 0)
    {
      continue;
    }
    const auto* literal = dynamic_cast<const ua::LiteralOperand*>(element.filter_operands()[0].get());
    if (literal == nullptr)
    {
      continue;
    }
    const Result<ua::NodeId> asNode = literal->value().to<ua::NodeId>();
    if (asNode.is_good())
    {
      types.push_back(asNode.value());
    }
  }
  return types;
}

bool is_allowed_event_where_operator(ua::FilterOperator filterOperator)
{
  switch (filterOperator)
  {
  case ua::FilterOperator::Equals:
  case ua::FilterOperator::IsNull:
  case ua::FilterOperator::GreaterThan:
  case ua::FilterOperator::LessThan:
  case ua::FilterOperator::GreaterThanOrEqual:
  case ua::FilterOperator::LessThanOrEqual:
  case ua::FilterOperator::Like:
  case ua::FilterOperator::Not:
  case ua::FilterOperator::Between:
  case ua::FilterOperator::InList:
  case ua::FilterOperator::And:
  case ua::FilterOperator::Or:
  case ua::FilterOperator::Cast:
  case ua::FilterOperator::OfType:
  case ua::FilterOperator::BitwiseAnd:
  case ua::FilterOperator::BitwiseOr:
    return true;
  case ua::FilterOperator::InView:
  case ua::FilterOperator::RelatedTo:
    return false;
  }
  return false;
}

// Build the OfType(typeId) ContentFilter element for the composite WhereClause.
ua::ContentFilterElement make_of_type_element(const ua::NodeId& typeId)
{
  ua::LiteralOperand operand;
  operand.value() = ua::Variant{typeId};
  ua::ContentFilterElement element;
  element.filter_operator() = ua::FilterOperator::OfType;
  element.filter_operands().push_back(
    ua::RefStructure<ua::Structure>{std::make_unique<ua::LiteralOperand>(std::move(operand))});
  return element;
}

/// Writes an OR-union of `OfType(type)` over @p types into @p where.
///
/// A ContentFilter is a TREE, not a list: OPC 10000-4 7.4.1 evaluates `elements[0]` as the root and reaches
/// the rest only through ElementOperands that reference them by index. Pushing N sibling OfType elements
/// therefore does NOT mean "any of these" - a conforming server evaluates the first and never looks at the
/// others, so every type but the first is silently dropped from the subscription. The union is built as a
/// right-leaning Or chain instead:
///
///     [0] Or(1, 2)   [1] OfType(A)   [2] Or(3, 4)   [3] OfType(B)   [4] OfType(C)
///
/// One type needs no Or at all, and an empty list leaves the WhereClause empty (== match everything).
void build_of_type_union(ua::ContentFilter& where, const std::vector<ua::NodeId>& types)
{
  if (types.empty())
  {
    return;
  }
  if (types.size() == 1)
  {
    where.elements().push_back(make_of_type_element(types.front()));
    return;
  }
  // Reserve the element slots first so the Or nodes can name indices that do not exist yet: element i's
  // Or references i+1 (the type at this level) and i+2 (the rest of the chain).
  for (std::size_t i = 0; i + 1 < types.size(); ++i)
  {
    const std::uint32_t base = static_cast<std::uint32_t>(where.elements().size());
    ua::ContentFilterElement orElement;
    orElement.filter_operator() = ua::FilterOperator::Or;
    auto leftOperand = std::make_unique<ua::ElementOperand>();
    leftOperand->index() = base + 1;
    auto rightOperand = std::make_unique<ua::ElementOperand>();
    // Slot base+2 is the next Or in the chain, except at the last level where it is the final OfType.
    rightOperand->index() = base + 2;
    orElement.filter_operands().push_back(ua::RefStructure<ua::Structure>{std::move(leftOperand)});
    orElement.filter_operands().push_back(ua::RefStructure<ua::Structure>{std::move(rightOperand)});
    where.elements().push_back(std::move(orElement));
    where.elements().push_back(make_of_type_element(types[i]));
    if (i + 2 == types.size())
    {
      where.elements().push_back(make_of_type_element(types[i + 1]));
    }
  }
}

// Decode one mandatory field out of a positional slot vector by its browse-name.
std::optional<ua::Variant> field_by_name(const EventNotification& notification, std::string_view name)
{
  return notification.field(name);
}

std::optional<ua::Variant> field_by_declaring_type(const EventNotification& notification,
  const ua::EventFilter& filter, std::string_view name, const ua::NodeId& declaringType)
{
  for (std::size_t index = 0; index < filter.select_clauses().size(); ++index)
  {
    const auto& clause = filter.select_clauses()[index];
    if (clause.type_definition_id() == declaringType && clause.browse_path().size() == 1 &&
        static_cast<std::string_view>(clause.browse_path()[0].name()) == name)
      return notification.fields[index];
  }
  return std::nullopt;
}

}  // namespace

std::shared_ptr<EventSubscriberImpl> EventSubscriberImpl::create(boost::asio::any_io_executor executor,
  std::weak_ptr<EventBackboneOps> backboneOps, ua::Logger logger, EventSubscriberPolicy policy,
  std::weak_ptr<ObserverSink> observerSink)
{
  return std::shared_ptr<EventSubscriberImpl>(new EventSubscriberImpl(
    std::move(executor), std::move(backboneOps), std::move(logger), policy, std::move(observerSink)));
}

EventSubscriberImpl::EventSubscriberImpl(boost::asio::any_io_executor executor,
  std::weak_ptr<EventBackboneOps> backboneOps, ua::Logger logger, EventSubscriberPolicy policy,
  std::weak_ptr<ObserverSink> observerSink)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)),
    mDeliveryStrand(boost::asio::make_strand(mExecutor)), mBackboneOps(std::move(backboneOps)),
    mLogger(std::move(logger)), mPolicy(policy), mObserverSink(std::move(observerSink))
{
  refresh_info_snapshot();
}

// ---- Consumer API ----

void EventSubscriberImpl::subscribe_async(EventSubscription subscription, EventNotificationCallback onEvent,
  std::function<void(SubscribeResult)> callback) noexcept
{
  // CL-MI-016: a present-but-empty filter is rejected at the entry point, before the strand hop.
  std::vector<ua::SimpleAttributeOperand> selectClauses = base_event_mandatory_select_clauses();
  std::vector<ua::NodeId> ofTypes;
  if (subscription.filter.has_value())
  {
    if (subscription.filter->select_clauses().size() == 0)
    {
      callback(SubscribeResult{StatusCode{Status::BadEventFilterInvalid},
        ua::make_error_detail("BadEventFilterInvalid",
          "event subscribe with an empty SelectClause list",
          "client.tier1.event_subscriber.empty_select_clauses")});
      return;
    }
    bool hasGeneralWhereClause = false;
    for (const auto& element : subscription.filter->where_clause().elements())
    {
      if (!is_allowed_event_where_operator(element.filter_operator()))
      {
        boost::asio::post(mExecutor,
          ua::async::guarded(mLogger,
            [callback = std::move(callback)]() mutable
            {
              callback(SubscribeResult{StatusCode{Status::BadFilterOperatorInvalid},
                ua::make_error_detail("BadFilterOperatorInvalid",
                  "event filter whereClause contains an operator not permitted by OPC UA Part 4",
                  "client.tier2.event_subscriber.invalid_where_operator")});
            }));
        return;
      }
      hasGeneralWhereClause |= element.filter_operator() != ua::FilterOperator::OfType;
    }
    // General ContentFilter graphs cannot be merged into the shared OfType union without changing their
    // element indices and boolean semantics. Preserve them intact on an isolated production backbone.
    subscription.requestDedicatedBackbone |= hasGeneralWhereClause;
    for (const auto& clause : subscription.filter->select_clauses())
    {
      selectClauses.push_back(clause);
    }
    ofTypes = extract_of_types(*subscription.filter);
  }

  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(),
              subscription = std::move(subscription),
              onEvent = std::move(onEvent),
              selectClauses = std::move(selectClauses),
              ofTypes = std::move(ofTypes),
              callback = std::move(callback)]() mutable
      {
        auto strong = self.lock();
        if (!strong)
        {
          callback(SubscribeResult{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        strong->do_subscribe(std::move(subscription),
          std::move(onEvent),
          std::move(selectClauses),
          std::move(ofTypes),
          std::move(callback));
      }](auto&) mutable { work(); })();
}

void EventSubscriberImpl::subscribe_to_type_async(ua::NodeId eventType, EventNotificationCallback onEvent,
  std::function<void(SubscribeResult)> callback) noexcept
{
  EventSubscription subscription;
  const auto auditCategory = known_audit_category(eventType);
  if (auditCategory.has_value())
    subscription.requestDedicatedBackbone = true;
  ua::EventFilter filter;
  for (auto& clause : base_event_mandatory_select_clauses())
  {
    filter.select_clauses().push_back(std::move(clause));
  }
  if (auditCategory.has_value())
  {
    for (const auto name : auditMandatoryFieldNames)
    {
      filter.select_clauses().push_back(
        make_typed_select_clause(name, ua::NodeId{ua::ObjectTypeId::AuditEventType}));
    }
    const bool selectAllCategories = *auditCategory == AuditEventCategory::Base;
    const bool securitySubtype = *auditCategory == AuditEventCategory::Security ||
                                 *auditCategory == AuditEventCategory::Channel ||
                                 *auditCategory == AuditEventCategory::Session;
    if (selectAllCategories || securitySubtype)
      filter.select_clauses().push_back(
        make_typed_select_clause("StatusCodeId", ua::NodeId{ua::ObjectTypeId::AuditSecurityEventType}));
    if (selectAllCategories || *auditCategory == AuditEventCategory::Channel)
      filter.select_clauses().push_back(
        make_typed_select_clause("SecureChannelId", ua::NodeId{ua::ObjectTypeId::AuditChannelEventType}));
    if (selectAllCategories || *auditCategory == AuditEventCategory::Session)
      filter.select_clauses().push_back(make_typed_select_clause(
        "SecureChannelId", ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType}));
    if (selectAllCategories || *auditCategory == AuditEventCategory::Session)
      filter.select_clauses().push_back(
        make_typed_select_clause("SessionId", ua::NodeId{ua::ObjectTypeId::AuditSessionEventType}));
    if (selectAllCategories || *auditCategory == AuditEventCategory::UpdateMethod)
    {
      filter.select_clauses().push_back(
        make_typed_select_clause("MethodId", ua::NodeId{ua::ObjectTypeId::AuditUpdateMethodEventType}));
      filter.select_clauses().push_back(
        make_typed_select_clause("InputArguments", ua::NodeId{ua::ObjectTypeId::AuditUpdateMethodEventType}));
    }
  }
  filter.where_clause().elements().push_back(make_of_type_element(eventType));
  subscription.filter = std::move(filter);
  subscribe_async(std::move(subscription), std::move(onEvent), std::move(callback));
}

void EventSubscriberImpl::subscribe_to_type_with_field_async(ua::NodeId eventType, std::string_view fieldName,
  EventNotificationCallback onEvent, std::function<void(SubscribeResult)> callback) noexcept
{
  subscribe_to_type_with_fields_async(
    std::move(eventType), {fieldName}, std::move(onEvent), std::move(callback));
}

void EventSubscriberImpl::subscribe_to_type_with_fields_async(ua::NodeId eventType,
  std::vector<std::string_view> fieldNames, EventNotificationCallback onEvent,
  std::function<void(SubscribeResult)> callback) noexcept
{
  // subscribe_async prepends the 8 BaseEventType mandatory clauses, so the filter carries ONLY the extra
  // typed field clause here (typeDefinitionId = eventType, so the browse path resolves from the concrete
  // type) plus the OfType(eventType) WhereClause. A DEDICATED backbone keeps this per-type field clause
  // unambiguous: `EventNotification::field(name)` is browse-name keyed, so two types sharing a browse-name
  // ("Changes") must NOT share a backbone or the second type's field would resolve to the wrong (or a null)
  // slot.
  EventSubscription subscription;
  subscription.requestDedicatedBackbone = true;
  ua::EventFilter filter;
  for (const std::string_view fieldName : fieldNames)
    filter.select_clauses().push_back(make_typed_select_clause(fieldName, eventType));
  filter.where_clause().elements().push_back(make_of_type_element(eventType));
  subscription.filter = std::move(filter);
  subscribe_async(std::move(subscription), std::move(onEvent), std::move(callback));
}

void EventSubscriberImpl::do_subscribe(EventSubscription subscription, EventNotificationCallback onEvent,
  std::vector<ua::SimpleAttributeOperand> selectClauses, std::vector<ua::NodeId> ofTypes,
  std::function<void(SubscribeResult)> callback)
{
  if (mClosing)
  {
    boost::asio::post(mExecutor,
      ua::async::guarded(mLogger,
        [callback = std::move(callback)]() mutable
        {
          callback(SubscribeResult{StatusCode{Status::BadConnectionClosed},
            ua::make_error_detail("BadConnectionClosed",
              "subscribe after EventSubscriber close",
              "client.tier1.event_subscriber.subscribe_after_close")});
        }));
    return;
  }

  if (!needs_subtype_closure(ofTypes, subscription.requestDedicatedBackbone))
  {
    finish_subscribe(std::move(subscription),
      std::move(onEvent),
      std::move(selectClauses),
      std::move(ofTypes),
      /*ofTypeClosure=*/{},
      std::move(callback));
    return;
  }

  // Serve the closure from cache when every requested root is already known: the type hierarchy is server
  // state that cannot change within a session, so the Nth consumer asking for ConditionType costs nothing.
  std::vector<ua::NodeId> cached;
  bool allCached = true;
  for (const auto& root : ofTypes)
  {
    const auto entry = mSubtypeClosureCache.find(root);
    if (entry == mSubtypeClosureCache.end())
    {
      allCached = false;
      break;
    }
    for (const auto& type : entry->second)
    {
      if (std::find(cached.begin(), cached.end(), type) == cached.end())
      {
        cached.push_back(type);
      }
    }
  }
  if (allCached)
  {
    finish_subscribe(std::move(subscription),
      std::move(onEvent),
      std::move(selectClauses),
      std::move(ofTypes),
      std::move(cached),
      std::move(callback));
    return;
  }

  auto ops = mBackboneOps.lock();
  if (!ops)
  {
    // No wire interface: isolate rather than guess. See the failure branch below for why.
    subscription.requestDedicatedBackbone = true;
    finish_subscribe(std::move(subscription),
      std::move(onEvent),
      std::move(selectClauses),
      std::move(ofTypes),
      /*ofTypeClosure=*/{},
      std::move(callback));
    return;
  }

  ops->resolve_event_subtypes_async(ofTypes,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [subscription = std::move(subscription),
        onEvent = std::move(onEvent),
        selectClauses = std::move(selectClauses),
        ofTypes,
        callback = std::move(callback)](
        EventSubscriberImpl& self, ua::Result<std::vector<ua::NodeId>> closure) mutable
      {
        if (!closure.is_good())
        {
          // Without a hierarchy no client-side type test can be correct, so isolate the consumer on its
          // own backbone and let the SERVER's OfType filter be the only filter that decides what it sees
          // (the same arrangement the audit types use). Matching the roots exactly instead would drop
          // every subtype. An Uncertain closure is not used or cached either: the type test acts on it.
          self.mLogger.warning(
            "event_subscriber: could not resolve the OfType subtype closure (status 0x{:08X}); isolating "
            "this consumer on its own backbone so the server filter stays authoritative",
            closure.status_code().as_uint32());
          subscription.requestDedicatedBackbone = true;
          self.finish_subscribe(std::move(subscription),
            std::move(onEvent),
            std::move(selectClauses),
            std::move(ofTypes),
            /*ofTypeClosure=*/{},
            std::move(callback));
          return;
        }
        // Cache per requested root. Each root's own closure is not separable from a multi-root walk, so a
        // single-root subscribe (the common case, and the only one the cache lookup can serve) caches the
        // whole answer; a multi-root one caches nothing and simply re-walks.
        if (ofTypes.size() == 1)
        {
          self.mSubtypeClosureCache[ofTypes.front()] = closure.value();
        }
        self.finish_subscribe(std::move(subscription),
          std::move(onEvent),
          std::move(selectClauses),
          std::move(ofTypes),
          std::move(closure).value(),
          std::move(callback));
      }));
}

bool EventSubscriberImpl::needs_subtype_closure(
  const std::vector<ua::NodeId>& ofTypes, bool dedicatedBackbone)
{
  if (ofTypes.empty() || dedicatedBackbone)
  {
    return false;
  }
  // Audit types are always given a dedicated backbone downstream, so the server filter is authoritative
  // for them too (this is the existing special case in consumer_matches, kept consistent here).
  return !std::ranges::any_of(
    ofTypes, [](const ua::NodeId& type) { return known_audit_category(type).has_value(); });
}

void EventSubscriberImpl::finish_subscribe(EventSubscription subscription, EventNotificationCallback onEvent,
  std::vector<ua::SimpleAttributeOperand> selectClauses, std::vector<ua::NodeId> ofTypes,
  std::vector<ua::NodeId> ofTypeClosure, std::function<void(SubscribeResult)> callback)
{
  if (mClosing)
  {
    // The subtype resolution is a wire round-trip, so a close can land while it is in flight.
    boost::asio::post(mExecutor,
      ua::async::guarded(mLogger,
        [callback = std::move(callback)]() mutable
        {
          callback(SubscribeResult{StatusCode{Status::BadConnectionClosed},
            ua::make_error_detail("BadConnectionClosed",
              "subscribe after EventSubscriber close",
              "client.tier1.event_subscriber.subscribe_after_close")});
        }));
    return;
  }

  const std::size_t backboneIndex =
    find_or_add_backbone(subscription.notifier, subscription.requestDedicatedBackbone);

  const MonitoredItemId handle = mNextClientHandle++;
  Consumer consumer;
  consumer.handle = handle;
  consumer.backboneIndex = backboneIndex;
  if (subscription.filter.has_value())
  {
    consumer.filter = *subscription.filter;
  }
  consumer.selectClauses = std::move(selectClauses);
  consumer.ofTypes = std::move(ofTypes);
  consumer.ofTypeClosure = std::move(ofTypeClosure);
  consumer.callback = std::move(onEvent);
  mConsumers.emplace(handle, std::move(consumer));
  mBackbones[backboneIndex].consumers.push_back(handle);

  push_filter_and_complete(backboneIndex, handle, std::move(callback));
}

std::size_t EventSubscriberImpl::find_or_add_backbone(const ua::NodeId& notifier, bool dedicated)
{
  if (!dedicated)
  {
    for (std::size_t i = 0; i < mBackbones.size(); ++i)
    {
      if (mBackbones[i].notifier == notifier && !mBackbones[i].dedicated)
      {
        return i;
      }
    }
  }
  Backbone backbone;
  backbone.notifier = notifier;
  backbone.backboneClientHandle = mNextClientHandle++;
  backbone.isDefaultServerBackbone = (notifier == ua::NodeId{ua::ObjectId::Server}) && !dedicated;
  backbone.dedicated = dedicated;
  mBackbones.push_back(std::move(backbone));
  return mBackbones.size() - 1;
}

ua::EventFilter EventSubscriberImpl::compute_composite_filter(const Backbone& backbone) const
{
  // SelectClauses: mandatories (slots 0..7) then the tail-appended union of every consumer's and tracker's
  // extra clauses (never re-order existing  -  CL-EVT-002 tail-append discipline).
  std::vector<ua::SimpleAttributeOperand> select = base_event_mandatory_select_clauses();
  std::vector<ua::NodeId> ofTypes;
  bool anyMatchAllConsumer = false;

  auto mergeSelect = [&select](const std::vector<ua::SimpleAttributeOperand>& more)
  {
    for (const auto& clause : more)
    {
      const bool present = std::any_of(select.begin(),
        select.end(),
        [&clause](const ua::SimpleAttributeOperand& existing)
        { return same_select_clause(existing, clause); });
      if (!present)
      {
        select.push_back(clause);
      }
    }
  };
  auto mergeTypes = [&ofTypes](const std::vector<ua::NodeId>& more)
  {
    for (const auto& type : more)
    {
      if (std::find(ofTypes.begin(), ofTypes.end(), type) == ofTypes.end())
      {
        ofTypes.push_back(type);
      }
    }
  };

  for (const MonitoredItemId handle : backbone.consumers)
  {
    const auto it = mConsumers.find(handle);
    if (it == mConsumers.end())
    {
      continue;
    }
    mergeSelect(it->second.selectClauses);
    // A consumer with no OfType set is match-all (nullopt filter == OfType(BaseEventType)); it contributes
    // nothing to the type union, so unioning it with a type-specific consumer would wrongly NARROW the
    // composite to that specific type and silently starve the match-all consumer of every other event.
    if (it->second.ofTypes.empty())
    {
      anyMatchAllConsumer = true;
    }
    else
    {
      mergeTypes(it->second.ofTypes);
    }
  }
  bool anyTracker = false;
  for (const auto& weak : backbone.trackers)
  {
    if (auto hook = weak.lock())
    {
      anyTracker = true;
      const ua::EventFilter contribution = hook->filter_contribution();
      std::vector<ua::SimpleAttributeOperand> hookSelect;
      hookSelect.reserve(contribution.select_clauses().size());
      for (const auto& clause : contribution.select_clauses())
      {
        hookSelect.push_back(clause);
      }
      mergeSelect(hookSelect);
      mergeTypes(extract_of_types(contribution));
    }
  }

  ua::EventFilter filter;
  for (auto& clause : select)
  {
    filter.select_clauses().push_back(std::move(clause));
  }
  // A dedicated consumer owns the complete server-side predicate. Unlike the shared backbone's safe
  // OfType union below, arbitrary basic ContentFilter graphs must retain their original element ordering,
  // operands, and element-index references.
  if (backbone.dedicated && backbone.trackers.empty() && backbone.consumers.size() == 1)
  {
    const auto consumer = mConsumers.find(backbone.consumers.front());
    if (consumer != mConsumers.end())
    {
      filter.where_clause() = consumer->second.filter.where_clause();
      return filter;
    }
  }
  // When ANY live consumer is match-all, the backbone must run with an EMPTY WhereClause (== match-all on
  // BaseEventType): a type union would starve the match-all consumer. A tracker still sees its Condition /
  // Refresh* events through the broadcast bypass, so the empty (broader) filter satisfies it too.
  if (anyMatchAllConsumer)
  {
    return filter;
  }
  // WhereClause: OR-union of OfType(type) clauses. The three Refresh* types are always present when >=1
  // tracker is attached (CL-AC-008). An empty union reduces to no WhereClause (== OfType(BaseEventType)).
  if (anyTracker)
  {
    mergeTypes({ua::NodeId{ua::ObjectTypeId::RefreshStartEventType},
      ua::NodeId{ua::ObjectTypeId::RefreshEndEventType},
      ua::NodeId{ua::ObjectTypeId::RefreshRequiredEventType}});
  }
  build_of_type_union(filter.where_clause(), ofTypes);
  return filter;
}

void EventSubscriberImpl::push_filter_and_complete(
  std::size_t backboneIndex, MonitoredItemId handle, std::function<void(SubscribeResult)> callback)
{
  Backbone& backbone = mBackbones[backboneIndex];
  ua::EventFilter composite = compute_composite_filter(backbone);

  auto ops = mBackboneOps.lock();
  if (!ops)
  {
    // The Connection is gone  -  remove the consumer we just added and fail on the executor.
    mConsumers.erase(handle);
    auto& consumers = backbone.consumers;
    consumers.erase(std::remove(consumers.begin(), consumers.end(), handle), consumers.end());
    boost::asio::post(mExecutor,
      ua::async::guarded(mLogger,
        [callback = std::move(callback)]() mutable
        {
          callback(SubscribeResult{StatusCode{Status::BadConnectionClosed},
            ua::make_error_detail("BadConnectionClosed",
              "EventSubscriber backbone ops gone",
              "client.tier1.event_subscriber.connection_gone")});
        }));
    return;
  }

  if (!backbone.created)
  {
    ops->create_backbone_async(backbone.notifier,
      composite,
      backbone.backboneClientHandle,
      mPolicy.defaultQueueSize,
      ua::async::post_borrowing(this,
        mStrand,
        mLogger,
        [backboneIndex, handle, composite, callback = std::move(callback)](
          EventSubscriberImpl& self, Result<EventBackboneCreated> result) mutable
        {
          Backbone& bb = self.mBackbones[backboneIndex];
          if (!result.has_value())
          {
            self.mConsumers.erase(handle);
            auto& list = bb.consumers;
            list.erase(std::remove(list.begin(), list.end(), handle), list.end());
            boost::asio::post(self.mExecutor,
              ua::async::guarded(self.mLogger,
                [callback = std::move(callback), result]() mutable
                { callback(SubscribeResult{result.status_code(), result.shared_detail()}); }));
            return;
          }
          bb.created = true;
          bb.subscriptionId = result.value().subscriptionId;
          bb.monitoredItemId = result.value().monitoredItemId;
          bb.lastSentFilter = std::move(composite);

          // The ids exist only now: trackers attach BEFORE the backbone MonitoredItem is
          // created, so the values published at attach were 0. ConditionRefresh cannot be
          // issued without them.
          for (auto& weakTracker : bb.trackers)
          {
            if (auto hook = weakTracker.lock())
            {
              hook->on_backbone_subscription_changed(bb.subscriptionId, bb.monitoredItemId);
            }
          }
          self.fire_filter_diagnostics(result.value().filterDiagnostics);
          MonitoredItem item = self.make_event_item(bb, handle);
          self.refresh_info_snapshot();
          // A Good subcode or an Uncertain code on the backbone's creation reaches the subscriber.
          boost::asio::post(self.mExecutor,
            ua::async::guarded(self.mLogger,
              [callback = std::move(callback), item = std::move(item), code = result.status_code()]() mutable
              { callback(ua::detail::held(std::move(item), code)); }));
        }));
    return;
  }

  if (composite == backbone.lastSentFilter)
  {
    MonitoredItem item = make_event_item(backbone, handle);
    refresh_info_snapshot();
    boost::asio::post(mExecutor,
      ua::async::guarded(mLogger,
        [callback = std::move(callback), item = std::move(item)]() mutable
        { callback(SubscribeResult{std::move(item)}); }));
    return;
  }

  ua::EventFilter previousFilter = backbone.lastSentFilter;
  ops->modify_backbone_filter_async(backbone.subscriptionId,
    backbone.monitoredItemId,
    backbone.backboneClientHandle,
    composite,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [backboneIndex, handle, composite, previousFilter, callback = std::move(callback)](
        EventSubscriberImpl& self, Result<EventFilterDiagnostics> result) mutable
      {
        Backbone& bb = self.mBackbones[backboneIndex];
        if (!result.has_value())
        {
          // Restore the prior filter and detach the failed consumer (no half-attached state, section 8.13.6).
          bb.lastSentFilter = std::move(previousFilter);
          self.mConsumers.erase(handle);
          auto& list = bb.consumers;
          list.erase(std::remove(list.begin(), list.end(), handle), list.end());
          boost::asio::post(self.mExecutor,
            ua::async::guarded(self.mLogger,
              [callback = std::move(callback), result]() mutable
              { callback(SubscribeResult{result.status_code(), result.shared_detail()}); }));
          return;
        }
        self.fire_filter_diagnostics(result.value());
        bb.lastSentFilter = std::move(composite);
        MonitoredItem item = self.make_event_item(bb, handle);
        self.refresh_info_snapshot();
        // A Good subcode or an Uncertain code on the filter's modification reaches the subscriber.
        boost::asio::post(self.mExecutor,
          ua::async::guarded(self.mLogger,
            [callback = std::move(callback), item = std::move(item), code = result.status_code()]() mutable
            { callback(ua::detail::held(std::move(item), code)); }));
      }));
}

MonitoredItem EventSubscriberImpl::make_event_item(const Backbone& backbone, MonitoredItemId handle)
{
  return MonitoredItemFactory::create(std::static_pointer_cast<MonitoredItemOwner>(shared_from_this()),
    handle,
    backbone.notifier,
    ua::AttributeId::EventNotifier,
    MonitoredItemKind::Event,
    ua::MonitoringMode::Reporting);
}

void EventSubscriberImpl::unsubscribe_async(
  MonitoredItem item, std::function<void(ua::VoidResult)> callback) noexcept
{
  mi_delete_async(item.client_handle(), std::move(callback));
}

// ---- MonitoredItemOwner (event consumers) ----

void EventSubscriberImpl::mi_delete_async(
  MonitoredItemId clientHandle, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(), clientHandle, callback = std::move(callback)]() mutable
      {
        auto strong = self.lock();
        if (!strong)
        {
          callback(VoidResult{StatusCode{Status::BadConnectionClosed},
            ua::make_error_detail("BadConnectionClosed",
              "event MonitoredItem delete after Connection gone",
              "client.tier1.event_subscriber.connection_gone")});
          return;
        }
        const auto it = strong->mConsumers.find(clientHandle);
        if (it == strong->mConsumers.end())
        {
          // section 8.13.6: unsubscribe with an unknown handle is idempotent Good.
          boost::asio::post(strong->mExecutor,
            ua::async::guarded(
              strong->mLogger, [callback = std::move(callback)]() mutable { callback(VoidResult{}); }));
          return;
        }
        const std::size_t backboneIndex = it->second.backboneIndex;
        strong->mConsumers.erase(it);
        auto& consumers = strong->mBackbones[backboneIndex].consumers;
        consumers.erase(std::remove(consumers.begin(), consumers.end(), clientHandle), consumers.end());
        strong->recompute_after_drop(backboneIndex, std::move(callback));
      }](auto&) mutable { work(); })();
}

void EventSubscriberImpl::recompute_after_drop(
  std::size_t backboneIndex, std::function<void(ua::VoidResult)> callback)
{
  Backbone& backbone = mBackbones[backboneIndex];
  const bool anyTrackerAlive = std::any_of(backbone.trackers.begin(),
    backbone.trackers.end(),
    [](const std::weak_ptr<EventTrackerHook>& weak) { return !weak.expired(); });

  auto ops = mBackboneOps.lock();

  // Last consumer AND no tracker AND not the warm default Server backbone  to  tear the backbone down.
  if (backbone.consumers.empty() && !anyTrackerAlive && !backbone.isDefaultServerBackbone && backbone.created)
  {
    if (!ops)
    {
      refresh_info_snapshot();
      boost::asio::post(mExecutor,
        ua::async::guarded(mLogger, [callback = std::move(callback)]() mutable { callback(VoidResult{}); }));
      return;
    }
    ops->delete_backbone_async(backbone.subscriptionId,
      backbone.monitoredItemId,
      ua::async::post_borrowing(this,
        mStrand,
        mLogger,
        [backboneIndex, callback = std::move(callback)](EventSubscriberImpl& self, VoidResult result) mutable
        {
          Backbone& bb = self.mBackbones[backboneIndex];
          bb.created = false;
          bb.subscriptionId = 0;
          bb.monitoredItemId = 0;
          self.refresh_info_snapshot();
          boost::asio::post(self.mExecutor,
            ua::async::guarded(self.mLogger,
              [callback = std::move(callback), result]() mutable { callback(std::move(result)); }));
        }));
    return;
  }

  // Otherwise: recompute the composite; issue a ModifyMonitoredItems only if it changed (never delete the
  // shared backbone  -  that would kill the surviving consumers/trackers).
  ua::EventFilter composite = compute_composite_filter(backbone);
  if (!backbone.created || composite == backbone.lastSentFilter || !ops)
  {
    refresh_info_snapshot();
    boost::asio::post(mExecutor,
      ua::async::guarded(mLogger, [callback = std::move(callback)]() mutable { callback(VoidResult{}); }));
    return;
  }
  ua::EventFilter previousFilter = backbone.lastSentFilter;
  ops->modify_backbone_filter_async(backbone.subscriptionId,
    backbone.monitoredItemId,
    backbone.backboneClientHandle,
    composite,
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [backboneIndex, composite, previousFilter, callback = std::move(callback)](
        EventSubscriberImpl& self, Result<EventFilterDiagnostics> result) mutable
      {
        Backbone& bb = self.mBackbones[backboneIndex];
        if (result.is_good())
        {
          self.fire_filter_diagnostics(result.value());
          bb.lastSentFilter = std::move(composite);
        }
        else
        {
          bb.lastSentFilter = std::move(previousFilter);
        }
        self.refresh_info_snapshot();
        boost::asio::post(self.mExecutor,
          ua::async::guarded(
            self.mLogger, [callback = std::move(callback)]() mutable { callback(VoidResult{}); }));
      }));
}

void EventSubscriberImpl::mi_set_mode_async(MonitoredItemId clientHandle, ua::MonitoringMode mode,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(), clientHandle, mode, callback = std::move(callback)]() mutable
      {
        auto strong = self.lock();
        if (!strong)
        {
          callback(VoidResult{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        const auto it = strong->mConsumers.find(clientHandle);
        VoidResult outcome{};
        if (it == strong->mConsumers.end())
        {
          outcome = VoidResult{StatusCode{Status::BadMonitoredItemIdInvalid},
            ua::make_error_detail("BadMonitoredItemIdInvalid",
              "set-mode on an unknown event consumer",
              "client.tier1.event_subscriber.unknown_consumer")};
        }
        else
        {
          // Per-consumer mode gates client-side delivery (the shared backbone MI stays Reporting; a
          // Disabled consumer simply stops receiving demuxed callbacks).
          it->second.mode = mode;
        }
        boost::asio::post(strong->mExecutor,
          ua::async::guarded(
            strong->mLogger, [callback = std::move(callback), outcome]() mutable { callback(outcome); }));
      }](auto&) mutable { work(); })();
}

void EventSubscriberImpl::mi_modify_async(MonitoredItemId clientHandle, MonitorRequest /*request*/,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  // The data-change MonitorRequest cannot express a new EventFilter, so an event-consumer filter change is
  // not modelled through the generic handle  -  callers re-subscribe. Fail explicitly (never silently no-op).
  ua::async::post_borrowing(this,
    mExecutor,
    mLogger,
    [work = [self = weak_from_this(), clientHandle, callback = std::move(callback)]() mutable
      {
        const bool known = [&]
        {
          auto strong = self.lock();
          return strong && strong->mConsumers.count(clientHandle) != 0;
        }();
        (void)known;
        callback(VoidResult{StatusCode{Status::BadNotSupported},
          ua::make_error_detail("BadNotSupported",
            "event-consumer filter modification is not expressible via a data-change MonitorRequest; "
            "re-subscribe with the new EventFilter",
            "client.tier1.event_subscriber.modify_not_supported")});
      }](auto&) mutable { work(); })();
}

// ---- Tracker hook surface ----

void EventSubscriberImpl::attach_tracker_async(
  std::shared_ptr<EventTrackerHook> hook, std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(), hook = std::move(hook), callback = std::move(callback)]() mutable
      {
        auto strong = self.lock();
        if (!strong || strong->mClosing)
        {
          if (callback)
          {
            callback(VoidResult{StatusCode{Status::BadConnectionClosed},
              ua::make_error_detail("BadConnectionClosed",
                "attach_tracker after close",
                "client.tier1.event_subscriber.attach_after_close")});
          }
          return;
        }
        // Trackers attach to the default Server backbone (creating it if needed).
        const std::size_t backboneIndex =
          strong->find_or_add_backbone(ua::NodeId{ua::ObjectId::Server}, false);
        Backbone& backbone = strong->mBackbones[backboneIndex];
        std::weak_ptr<EventTrackerHook> weakHook = hook;
        backbone.trackers.push_back(weakHook);
        backbone.pendingFirstEvent.push_back(hook);
        strong->mTrackerHooks.push_back(weakHook);

        // Publish the backbone's ids: ConditionRefresh takes the SubscriptionId as its one mandatory
        // argument and ConditionRefresh2 additionally takes the MonitoredItemId. The tracker reaches
        // the wire through a method-call interface that knows nothing about subscriptions, so this is its
        // only source. Republished after a recreate below, since both change with the new session.
        hook->on_backbone_subscription_changed(backbone.subscriptionId, backbone.monitoredItemId);

        // Reuse the composite-recompute machinery: adding a tracker only widens the filter  -  model it as a
        // "no consumer added" recompute-and-modify-if-changed, delivering the tracker's start callback.
        ua::EventFilter composite = strong->compute_composite_filter(backbone);
        auto ops = strong->mBackboneOps.lock();
        if (!backbone.created)
        {
          if (!ops)
          {
            strong->deliver_void(std::move(callback), VoidResult{StatusCode{Status::BadConnectionClosed}});
            return;
          }
          ops->create_backbone_async(backbone.notifier,
            composite,
            backbone.backboneClientHandle,
            strong->mPolicy.defaultQueueSize,
            ua::async::post_borrowing(strong.get(),
              strong->mStrand,
              strong->mLogger,
              [backboneIndex, composite, callback = std::move(callback)](
                EventSubscriberImpl& s, Result<EventBackboneCreated> result) mutable
              {
                Backbone& bb = s.mBackbones[backboneIndex];
                if (!result.has_value())
                {
                  s.deliver_void(
                    std::move(callback), VoidResult{result.status_code(), result.shared_detail()});
                  return;
                }
                bb.created = true;
                bb.subscriptionId = result.value().subscriptionId;
                bb.monitoredItemId = result.value().monitoredItemId;
                bb.lastSentFilter = std::move(composite);

                // The ids exist only now: trackers attach BEFORE the backbone MonitoredItem is
                // created, so the values published at attach were 0. ConditionRefresh cannot be
                // issued without them.
                for (auto& weakTracker : bb.trackers)
                {
                  if (auto trackerHook = weakTracker.lock())
                  {
                    trackerHook->on_backbone_subscription_changed(bb.subscriptionId, bb.monitoredItemId);
                  }
                }
                s.refresh_info_snapshot();
                // A Good subcode or an Uncertain code on the backbone's creation reaches the tracker.
                s.deliver_void(std::move(callback), VoidResult{result.status_code()});
              }));
          return;
        }
        if (composite == backbone.lastSentFilter)
        {
          strong->refresh_info_snapshot();
          strong->deliver_void(std::move(callback), VoidResult{});
          return;
        }
        if (!ops)
        {
          strong->deliver_void(std::move(callback), VoidResult{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        ua::EventFilter previousFilter = backbone.lastSentFilter;
        ops->modify_backbone_filter_async(backbone.subscriptionId,
          backbone.monitoredItemId,
          backbone.backboneClientHandle,
          composite,
          ua::async::post_borrowing(strong.get(),
            strong->mStrand,
            strong->mLogger,
            [backboneIndex, composite, previousFilter, callback = std::move(callback)](
              EventSubscriberImpl& s, Result<EventFilterDiagnostics> result) mutable
            {
              Backbone& bb = s.mBackbones[backboneIndex];
              if (!result.has_value())
              {
                bb.lastSentFilter = std::move(previousFilter);
                s.deliver_void(std::move(callback), VoidResult{result.status_code(), result.shared_detail()});
                return;
              }
              s.fire_filter_diagnostics(result.value());
              bb.lastSentFilter = std::move(composite);
              s.refresh_info_snapshot();
              // A Good subcode or an Uncertain code on the filter's modification reaches the tracker.
              s.deliver_void(std::move(callback), VoidResult{result.status_code()});
            }));
      }](auto&) mutable { work(); })();
}

void EventSubscriberImpl::widen_tracker_filter_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(), callback = std::move(callback)]() mutable
      {
        auto strong = self.lock();
        if (!strong)
        {
          callback(VoidResult{StatusCode{Status::BadConnectionClosed}});
          return;
        }
        // Recompute every backbone that has trackers; issue ModifyMI only where the composite changed.
        for (std::size_t i = 0; i < strong->mBackbones.size(); ++i)
        {
          Backbone& backbone = strong->mBackbones[i];
          if (backbone.trackers.empty() || !backbone.created)
          {
            continue;
          }
          ua::EventFilter composite = strong->compute_composite_filter(backbone);
          if (composite == backbone.lastSentFilter)
          {
            continue;
          }
          auto ops = strong->mBackboneOps.lock();
          if (!ops)
          {
            break;
          }
          ua::EventFilter previousFilter = backbone.lastSentFilter;
          ops->modify_backbone_filter_async(backbone.subscriptionId,
            backbone.monitoredItemId,
            backbone.backboneClientHandle,
            composite,
            ua::async::post_borrowing(strong.get(),
              strong->mStrand,
              strong->mLogger,
              [i, composite, previousFilter](
                EventSubscriberImpl& s, Result<EventFilterDiagnostics> result) mutable
              {
                Backbone& bb = s.mBackbones[i];
                if (result.is_good())
                {
                  s.fire_filter_diagnostics(result.value());
                }
                bb.lastSentFilter = result.is_good() ? std::move(composite) : std::move(previousFilter);
                s.refresh_info_snapshot();
              }));
        }
        strong->deliver_void(std::move(callback), VoidResult{});
      }](auto&) mutable { work(); })();
}

// ---- Publish demux ----

void EventSubscriberImpl::on_publish_events_async(std::uint32_t backboneClientHandle,
  std::vector<ua::EventFieldList> notifications, std::function<void()> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(),
              backboneClientHandle,
              notifications = std::move(notifications),
              callback = std::move(callback)]() mutable
      {
        auto strong = self.lock();
        if (!strong)
        {
          if (callback)
          {
            callback();
          }
          return;
        }
        strong->dispatch_notifications(backboneClientHandle, notifications);
        if (callback)
        {
          boost::asio::post(strong->mExecutor,
            ua::async::guarded(strong->mLogger, [callback = std::move(callback)]() mutable { callback(); }));
        }
      }](auto&) mutable { work(); })();
}

void EventSubscriberImpl::on_reconnect_recovered_async(
  std::vector<std::uint32_t> affectedSubscriptionIds, BackboneRecoveryReason reason) noexcept
{
  // Strand entry (the connection strand calls this from any context; the subscriber strand serialises the
  // work  -  no reach-in). Mirrors the guarded weak-self post idiom used by every other public method here.
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(),
              affectedSubscriptionIds = std::move(affectedSubscriptionIds),
              reason]() mutable
      {
        auto strong = self.lock();
        if (!strong || strong->mClosing)
        {
          return;
        }
        for (auto& backbone : strong->mBackbones)
        {
          if (!backbone.created)
          {
            continue;
          }
          // Reset ONLY the backbones that were RECREATED this reconnect (their create-time subscriptionId is
          // in the affected set). A transferred/preserved backbone kept its id server-side and its
          // old-session Refresh windows drain via Republish  -  resetting it would deliver a FALSE
          // Bad_SessionClosed to an in-flight ConditionRefresh and re-arm a redundant one (Finding 1).
          // `Backbone::subscriptionId` still holds the OLD (create-time) id here  -  the pipeline recovery
          // does not update it  -  so it pairs directly against each staged rekey's old id.
          const bool affected = std::find(affectedSubscriptionIds.begin(),
                                  affectedSubscriptionIds.end(),
                                  backbone.subscriptionId) != affectedSubscriptionIds.end();
          if (!affected)
          {
            continue;
          }
          // The recreated MI on the new session has not yet delivered its first post-recovery event: re-arm
          // the one-shot so the next event re-issues a fresh ConditionRefresh (resync, CL-AC-003).
          backbone.firstEventDelivered = false;
          // Re-arm the live trackers and prune the expired weaks in one pass.
          std::vector<std::weak_ptr<EventTrackerHook>> liveTrackers;
          liveTrackers.reserve(backbone.trackers.size());
          for (auto& weakTracker : backbone.trackers)
          {
            auto hook = weakTracker.lock();
            if (!hook)
            {
              continue;  // expired tracker  -  prune
            }
            liveTrackers.push_back(weakTracker);
            // Reset the tracker's dead (old-session) refresh state. The forward weak-locks and never throws
            // (recovery is attacker-influenceable  -  no throw out of this on-strand handler). @p reason is
            // threaded so the tracker delivers an accurate reset status/message (Finding 2 / R4).
            hook->on_backbone_recovered(reason);
            // The recreate put the backbone on a NEW subscription and MonitoredItem; a refresh issued
            // with the old ids would be refused (Bad_SubscriptionIdInvalid) or replay the wrong item.
            hook->on_backbone_subscription_changed(backbone.subscriptionId, backbone.monitoredItemId);
            // Re-arm the first-event one-shot, skipping a hook already pending so a double-fire cannot issue
            // a duplicate ConditionRefresh.
            const bool alreadyPending = std::any_of(backbone.pendingFirstEvent.begin(),
              backbone.pendingFirstEvent.end(),
              [&hook](const std::shared_ptr<EventTrackerHook>& pending) { return pending == hook; });
            if (!alreadyPending)
            {
              backbone.pendingFirstEvent.push_back(hook);
            }
          }
          backbone.trackers = std::move(liveTrackers);
        }
        strong->refresh_info_snapshot();
      }](auto&) mutable { work(); })();
}

void EventSubscriberImpl::on_redundancy_switch_recovered_async(ua::RedundancySupport mode) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(), mode]
      {
        auto strong = self.lock();
        if (!strong || strong->mClosing || !strong->mAlarmTracker)
        {
          return;
        }
        strong->mAlarmTracker->on_redundancy_switch_recovered_async(mode);
      }](auto&) mutable { work(); })();
}

void EventSubscriberImpl::dispatch_notifications(
  std::uint32_t backboneClientHandle, const std::vector<ua::EventFieldList>& notifications)
{
  // Key by the CLIENT-assigned backbone handle (what the server echoes in EventFieldList.client_handle),
  // NOT the server monitoredItemId: the wire carries no monitored-item id, and the client handle is stable
  // across a session-recreate (monitoredItemId is reassigned). See design section 8.13 / the demux wiring.
  const auto backboneIt = std::find_if(mBackbones.begin(),
    mBackbones.end(),
    [backboneClientHandle](const Backbone& backbone)
    { return backbone.created && backbone.backboneClientHandle == backboneClientHandle; });
  if (backboneIt == mBackbones.end())
  {
    return;
  }
  Backbone& backbone = *backboneIt;
  mLastPublishFieldListCount = notifications.size();

  // Fire the one-shot on_first_event_after_attach for any tracker awaiting it (CL-AC-003).
  if (!notifications.empty() && !backbone.pendingFirstEvent.empty())
  {
    std::vector<std::shared_ptr<EventTrackerHook>> pending;
    pending.swap(backbone.pendingFirstEvent);
    backbone.firstEventDelivered = true;
    for (auto& hook : pending)
    {
      hook->on_first_event_after_attach();
    }
  }

  for (const auto& fieldList : notifications)
  {
    const auto decoded = decode_notification(backbone, fieldList);
    if (!decoded.has_value())
    {
      continue;  // dropped (field-count mismatch / missing mandatory)  -  advisory emitted in decode
    }
    dispatch_one(backbone, *decoded);
  }
  refresh_info_snapshot();
}

std::optional<EventNotification> EventSubscriberImpl::decode_notification(
  const Backbone& backbone, const ua::EventFieldList& fieldList) const
{
  const auto& selectClauses = backbone.lastSentFilter.select_clauses();
  // CL-EVT-002: field-count mismatch  to  drop (a malformed event must not be delivered silently). Part 4
  // section 7.25.3 requires eventFields to be a 1:1 positional match with the filter's selectClauses.
  if (fieldList.event_fields().size() != selectClauses.size())
  {
    mLogger.warning(
      "event decode: EventFieldList carries {} fields but the backbone filter has {} SelectClauses; "
      "dropping the malformed event (CL-EVT-002)",
      fieldList.event_fields().size(),
      selectClauses.size());
    fire_decode_advisory(
      ua::ErrorDetail::build("EventFieldCountMismatch",
        "EventFieldList field count does not match the backbone filter SelectClause count; dropping the "
        "malformed event (CL-EVT-002)",
        "client.tier2.event_subscriber.field_count_mismatch")
        .context(ua::ContextKeys::sizeActual, std::to_string(fieldList.event_fields().size()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(selectClauses.size())));
    return std::nullopt;
  }
  EventNotification notification;
  notification.itemId = fieldList.client_handle();
  notification.fields.reserve(selectClauses.size());
  notification.fieldPaths.reserve(selectClauses.size());
  for (std::size_t i = 0; i < selectClauses.size(); ++i)
  {
    const ua::Variant& value = fieldList.event_fields()[i];
    notification.fields.push_back(value.empty() ? std::nullopt : std::optional<ua::Variant>{value});
    std::vector<ua::QualifiedName> path;
    for (const auto& segment : selectClauses[i].browse_path())
    {
      path.push_back(segment);
    }
    notification.fieldPaths.push_back(std::move(path));
  }

  // CL-EVT-001: EventType is required for demux; drop if absent/undecodable (advisory on drop). EventType is
  // one of the four fields Part 5 section 6.4.2 guarantees "shall always be returned as value"; an absent or
  // status-coded value fails to decode to a NodeId here and is dropped below.
  const std::optional<ua::Variant> eventTypeField = field_by_name(notification, "EventType");
  if (!eventTypeField.has_value())
  {
    mLogger.warning("event decode: EventType field absent; dropping the event (CL-EVT-001)");
    fire_decode_advisory(ua::make_error_detail("MandatoryEventFieldMissing",
      "Mandatory BaseEventType field EventType is absent as a value; dropping the malformed event "
      "(CL-EVT-001)",
      "client.tier2.event_subscriber.mandatory_field_missing"));
    return std::nullopt;
  }
  const Result<ua::NodeId> eventType = eventTypeField->to<ua::NodeId>();
  if (!eventType.has_value())
  {
    mLogger.warning(
      "event decode: EventType field is not a decodable NodeId; dropping the event (CL-EVT-001)");
    fire_decode_advisory(ua::make_error_detail("MandatoryEventFieldUndecodable",
      "Mandatory BaseEventType field EventType is not a decodable NodeId; dropping the malformed event "
      "(CL-EVT-001)",
      "client.tier2.event_subscriber.mandatory_field_undecodable"));
    return std::nullopt;
  }
  notification.eventTypeId = eventType.value();

  // EXEMPT the Part 9 (A&C) Refresh* CONTROL events from the mandatory-field hard-drop (section 3.1 EV1
  // re-review). RefreshStart / RefreshEnd / RefreshRequired are SYNTHETIC control events (Part 9
  // section 4.5), not application data: the tracker correlates a refresh window PURELY on EventId
  // (Time/ReceiveTime are never read from them). The four-field always-present-as-value guarantee (Part 5
  // section 6.4.2) governs BaseEventType DATA fields; gating a control event's delivery on it means a server
  // that cut a corner on a synthetic RefreshEnd's ReceiveTime would have it DROPPED  -  handle_refresh_end
  // never drains mActiveRefreshWindows, mRefreshInProgress never clears, and every subsequent refresh_async
  // returns Bad_RefreshInProgress: the entire ConditionRefresh subsystem wedges permanently. Deliver these
  // best-effort (as before this slice); the field-count + EventType checks above still apply (EventType is
  // what classifies the event as Refresh in the first place).
  const bool isRefreshControlEvent =
    notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshStartEventType} ||
    notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshEndEventType} ||
    notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshRequiredEventType};

  // CL-EVT-001: enforce the remaining three normatively-guaranteed BaseEventType fields  -  EventId, Time,
  // ReceiveTime. Part 5 section 6.4.2 requires each "shall always be returned as value and the Server is not
  // allowed to return a StatusCode ... indicating an error". A missing (absent / empty Variant  to  nullopt)
  // OR a status-coded value  to  the event is malformed  to  drop + advisory. The hard-drop is scoped to
  // EXACTLY these four fields (EventType handled above); the OPTIONAL / best-effort fields
  // (SourceNode/SourceName/Message/ Severity) are NEVER hard-dropped  -  a slightly non-compliant server that
  // omits one must still deliver the event, surfacing the field as nullopt (CL-MI-017 three-state).
  for (const std::string_view mandatoryFieldName :
    {std::string_view{"EventId"}, std::string_view{"Time"}, std::string_view{"ReceiveTime"}})
  {
    if (isRefreshControlEvent)
    {
      break;  // control events are exempt (see above)  -  deliver best-effort so the refresh window can drain
    }
    const std::optional<ua::Variant> value = field_by_name(notification, mandatoryFieldName);
    if (!value.has_value())
    {
      mLogger.warning(
        "event decode: mandatory BaseEventType field {} is absent as a value; dropping the event "
        "(CL-EVT-001)",
        mandatoryFieldName);
      fire_decode_advisory(ua::ErrorDetail::build("MandatoryEventFieldMissing",
        "A mandatory BaseEventType field is absent as a value; dropping the malformed event (CL-EVT-001)",
        "client.tier2.event_subscriber.mandatory_field_missing")
                             .context(ua::ContextKeys::fieldName, std::string{mandatoryFieldName}));
      return std::nullopt;
    }
    if (value->is_status_code())
    {
      mLogger.warning(
        "event decode: mandatory BaseEventType field {} carries a StatusCode instead of a value; dropping "
        "the "
        "event (CL-EVT-001)",
        mandatoryFieldName);
      fire_decode_advisory(ua::ErrorDetail::build("MandatoryEventFieldStatusCoded",
        "A mandatory BaseEventType field carries a StatusCode instead of a value; dropping the malformed "
        "event (CL-EVT-001)",
        "client.tier2.event_subscriber.mandatory_field_status_coded")
                             .context(ua::ContextKeys::fieldName, std::string{mandatoryFieldName}));
      return std::nullopt;
    }
  }

  // Best-effort decode of the mandatory fields into the struct's convenience accessors. Time / ReceiveTime
  // are decoded here (their struct fields exist but were previously never populated) so the enforcement above
  // and downstream consumers see them.
  if (const auto eventId = field_by_name(notification, "EventId"))
  {
    if (const auto decoded = eventId->to<ua::ByteString>(); decoded.is_good())
    {
      notification.eventId = decoded.value();
    }
  }
  if (const auto sourceNode = field_by_name(notification, "SourceNode"))
  {
    if (const auto decoded = sourceNode->to<ua::NodeId>(); decoded.is_good())
    {
      notification.sourceNode = decoded.value();
    }
  }
  if (const auto sourceName = field_by_name(notification, "SourceName"))
  {
    if (const auto decoded = sourceName->to<ua::String>(); decoded.is_good())
    {
      notification.sourceName = decoded.value();
    }
  }
  if (const auto message = field_by_name(notification, "Message"))
  {
    if (const auto decoded = message->to<ua::LocalizedText>(); decoded.is_good())
    {
      notification.message = decoded.value();
    }
  }
  if (const auto severity = field_by_name(notification, "Severity"))
  {
    if (const auto decoded = severity->to<std::uint16_t>(); decoded.is_good())
    {
      notification.severity = decoded.value();
    }
  }
  if (const auto time = field_by_name(notification, "Time"))
  {
    if (const auto decoded = time->to<ua::DateTime>(); decoded.is_good())
    {
      notification.time = decoded.value();
    }
  }
  if (const auto receiveTime = field_by_name(notification, "ReceiveTime"))
  {
    if (const auto decoded = receiveTime->to<ua::DateTime>(); decoded.is_good())
    {
      notification.receiveTime = decoded.value();
    }
  }

  const auto backboneTypes = extract_of_types(backbone.lastSentFilter);
  const bool authoritativeAuditBackbone = std::ranges::any_of(
    backboneTypes, [](const ua::NodeId& type) { return known_audit_category(type).has_value(); });
  const auto knownAuditCategory = known_audit_category(notification.eventTypeId);
  if (knownAuditCategory.has_value() || authoritativeAuditBackbone)
  {
    const auto missingOrBad = [this](std::string_view fieldName, std::string_view reason)
    {
      fire_decode_advisory(ua::ErrorDetail::build("AuditEventMandatoryFieldInvalid",
        "A mandatory AuditEventType field is missing or has the wrong type",
        "client.tier2.event_subscriber.audit_mandatory_field_invalid")
                             .context(ua::ContextKeys::fieldName, std::string{fieldName})
                             .context(ua::ContextKeys::errorMessage, std::string{reason}));
    };
    const auto actionTimeStamp = field_by_name(notification, "ActionTimeStamp");
    const auto status = field_by_name(notification, "Status");
    const auto serverId = field_by_name(notification, "ServerId");
    const auto clientAuditEntryId = field_by_name(notification, "ClientAuditEntryId");
    const auto clientUserId = field_by_name(notification, "ClientUserId");
    if (!actionTimeStamp || !status || !serverId || !clientAuditEntryId || !clientUserId)
    {
      const auto missing = !actionTimeStamp      ? "ActionTimeStamp"
                           : !status             ? "Status"
                           : !serverId           ? "ServerId"
                           : !clientAuditEntryId ? "ClientAuditEntryId"
                                                 : "ClientUserId";
      missingOrBad(missing, "field is absent");
      return notification;
    }
    const auto decodedActionTimeStamp = actionTimeStamp->to<ua::DateTime>();
    const auto decodedStatus = status->to<bool>();
    const auto decodedServerId = serverId->to<ua::String>();
    const auto decodedClientAuditEntryId = clientAuditEntryId->to<ua::String>();
    const auto decodedClientUserId = clientUserId->to<ua::String>();
    if (decodedActionTimeStamp.is_bad() || decodedStatus.is_bad() || decodedServerId.is_bad() ||
        decodedClientAuditEntryId.is_bad() || decodedClientUserId.is_bad())
    {
      const auto invalid = decodedActionTimeStamp.is_bad()      ? "ActionTimeStamp"
                           : decodedStatus.is_bad()             ? "Status"
                           : decodedServerId.is_bad()           ? "ServerId"
                           : decodedClientAuditEntryId.is_bad() ? "ClientAuditEntryId"
                                                                : "ClientUserId";
      missingOrBad(invalid, "field has the wrong type");
      return notification;
    }
    notification.audit = AuditEventFields{.actionTimeStamp = decodedActionTimeStamp.value(),
      .status = decodedStatus.value(),
      .serverId = decodedServerId.value(),
      .clientAuditEntryId = decodedClientAuditEntryId.value(),
      .clientUserId = decodedClientUserId.value()};

    AuditSubtypeFields subtype;
    subtype.category = knownAuditCategory.value_or(AuditEventCategory::UnknownSubtype);
    if (subtype.category == AuditEventCategory::Security || subtype.category == AuditEventCategory::Channel ||
        subtype.category == AuditEventCategory::Session)
    {
      if (const auto statusCodeId = field_by_name(notification, "StatusCodeId"))
      {
        if (statusCodeId->is_status_code())
          subtype.statusCodeId = statusCodeId->as<ua::StatusCode>();
        else
          missingOrBad("StatusCodeId", "optional field has the wrong type");
      }
    }
    const auto decodeOptional = [&missingOrBad, &notification]<typename ValueT>(
                                  std::string_view name) -> std::optional<ValueT>
    {
      const auto field = field_by_name(notification, name);
      if (!field)
      {
        missingOrBad(name, "category field is absent");
        return std::nullopt;
      }
      const auto decoded = field->template to<ValueT>();
      if (!decoded.has_value())
      {
        missingOrBad(name, "category field has the wrong type");
        return std::nullopt;
      }
      return decoded.value();
    };
    switch (subtype.category)
    {
    case AuditEventCategory::Channel:
      if (const auto secureChannelId = field_by_declaring_type(notification,
            backbone.lastSentFilter,
            "SecureChannelId",
            ua::NodeId{ua::ObjectTypeId::AuditChannelEventType}))
      {
        const auto decoded = secureChannelId->to<ua::String>();
        if (decoded.is_good())
          subtype.secureChannelId = decoded.value();
        else
          missingOrBad("SecureChannelId", "channel field has the wrong type");
      }
      else
        missingOrBad("SecureChannelId", "channel field is absent");
      break;
    case AuditEventCategory::Session:
      subtype.sessionId = decodeOptional.template operator()<ua::NodeId>("SessionId");
      if (notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType})
      {
        if (const auto secureChannelId = field_by_declaring_type(notification,
              backbone.lastSentFilter,
              "SecureChannelId",
              ua::NodeId{ua::ObjectTypeId::AuditCreateSessionEventType}))
        {
          const auto decoded = secureChannelId->to<ua::String>();
          if (decoded.is_good())
            subtype.secureChannelId = decoded.value();
          else
            missingOrBad("SecureChannelId", "CreateSession field has the wrong type");
        }
        else
          missingOrBad("SecureChannelId", "CreateSession field is absent");
      }
      break;
    case AuditEventCategory::UpdateMethod:
      subtype.methodId = decodeOptional.template operator()<ua::NodeId>("MethodId");
      if (const auto inputArguments = field_by_name(notification, "InputArguments"))
        subtype.inputArguments = *inputArguments;
      else
        missingOrBad("InputArguments", "category field is absent");
      break;
    case AuditEventCategory::Base:
    case AuditEventCategory::Security:
    case AuditEventCategory::Update:
    case AuditEventCategory::UnknownSubtype:
      break;
    }
    notification.auditSubtype = std::move(subtype);
  }
  return notification;
}

void EventSubscriberImpl::fire_decode_advisory(std::shared_ptr<const ua::ErrorDetail> detail) const
{
  // The advisory sink is weak (section 7.8, no ownership cycle); a gone / uninstalled sink is a clean skip.
  // The sink fans out on its OWN delivery strand (never re-entering this subscriber strand), so this is safe
  // to call from the on-strand decode path (the design specification).
  if (const auto sink = mObserverSink.lock())
  {
    sink->fire_advisory_diagnostic(std::move(detail));
  }
}

void EventSubscriberImpl::fire_filter_diagnostics(const EventFilterDiagnostics& diagnostics) const
{
  for (const auto& diagnostic : diagnostics)
  {
    auto detail = ua::ErrorDetail::build("EventFilterResultRejected",
      "the server rejected part of the requested event filter",
      "client.tier2.event_subscriber.event_filter_result");
    detail.cause(diagnostic.status);
    switch (diagnostic.kind)
    {
    case EventFilterDiagnosticKind::SelectClause:
      detail.context(ua::ContextKeys::fieldName, std::string{"selectClauseResults"})
        .context(ua::ContextKeys::operationIndex, diagnostic.index);
      break;
    case EventFilterDiagnosticKind::WhereClauseElement:
      detail.context(ua::ContextKeys::fieldName, std::string{"whereClauseResult.elementResults"})
        .context(ua::ContextKeys::operationIndex, diagnostic.index);
      break;
    case EventFilterDiagnosticKind::WhereClauseOperand:
      detail
        .context(
          ua::ContextKeys::fieldName, std::string{"whereClauseResult.elementResults.operandStatusCodes"})
        .context(ua::ContextKeys::index, diagnostic.index)
        .context(ua::ContextKeys::operationIndex, diagnostic.operandIndex);
      break;
    }
    fire_decode_advisory(std::move(detail));
  }
}

void EventSubscriberImpl::dispatch_one(Backbone& backbone, const EventNotification& notification)
{
  // Part 4 section 5.12.1.5: EventQueueOverflowEventType is ordinary event data AND the server's loss signal.
  // Preserve normal callback delivery below while also surfacing an operational advisory.
  if (notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::EventQueueOverflowEventType})
  {
    fire_decode_advisory(ua::ErrorDetail::build("EventQueueOverflow",
      "the Server discarded one or more queued Events for this MonitoredItem",
      "client.tier2.event_subscriber.queue_overflow")
                           .context(ua::ContextKeys::monitoredItemId, notification.itemId));
  }

  // CL-AC-008: the three Refresh* types bypass the per-consumer demux and broadcast to every tracker.
  const bool isRefresh = notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshStartEventType} ||
                         notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshEndEventType} ||
                         notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshRequiredEventType};

  if (isRefresh)
  {
    for (auto& weak : backbone.trackers)
    {
      auto hook = weak.lock();
      if (!hook)
      {
        continue;
      }
      if (notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshStartEventType})
      {
        hook->on_refresh_start_event(notification);
      }
      else if (notification.eventTypeId == ua::NodeId{ua::ObjectTypeId::RefreshEndEventType})
      {
        hook->on_refresh_end_event(notification);
      }
      else
      {
        hook->on_refresh_required_event(notification);
      }
    }
    return;
  }

  // Per-consumer demux: a consumer matches when it requested this event type (or is match-all).
  for (const MonitoredItemId handle : backbone.consumers)
  {
    const auto it = mConsumers.find(handle);
    if (it == mConsumers.end())
    {
      continue;
    }
    const Consumer& consumer = it->second;
    if (consumer.mode == ua::MonitoringMode::Disabled)
    {
      continue;
    }
    if (!consumer_matches(consumer, notification.eventTypeId))
    {
      continue;
    }
    if (consumer.callback)
    {
      // CL-MI-026: deliver the user event callback on the dedicated FIFO delivery strand (not the bare
      // multi-threaded executor), so per-item events arrive in order and non-reentrant.
      boost::asio::post(mDeliveryStrand,
        ua::async::guarded(
          mLogger, [callback = consumer.callback, notification]() mutable { callback(notification); }));
    }
  }

  // Trackers also see the non-Refresh feed (they filter internally).
  for (auto& weak : backbone.trackers)
  {
    if (auto hook = weak.lock())
    {
      hook->on_event(notification);
    }
  }
}

bool EventSubscriberImpl::consumer_matches(const Consumer& consumer, const ua::NodeId& eventTypeId) const
{
  if (consumer.ofTypes.empty())
  {
    return true;  // match-all (BaseEventType)
  }
  if (std::ranges::any_of(
        consumer.ofTypes, [](const ua::NodeId& type) { return known_audit_category(type).has_value(); }))
  {
    // Known audit types are always assigned a dedicated backbone. The server-side OfType filter is therefore
    // authoritative that every event delivered on it is a standard or custom AuditEvent subtype.
    return true;
  }
  // Match against the SUBTYPE CLOSURE, not the requested roots: OfType is subtype-inclusive (OPC 10000-4
  // 7.4.4.5), so a server given OfType(ConditionType) delivers every alarm subtype through that filter and
  // the demux must accept them. On a shared backbone the wire filter is the UNION of the consumers'
  // filters, which is what makes this test required.
  //
  // An empty closure means the consumer is on a dedicated backbone (by request, or because the closure
  // could not be resolved), so the server's own filter is authoritative and everything delivered on that
  // backbone is for this consumer.
  if (consumer.ofTypeClosure.empty())
  {
    return true;
  }
  return std::find(consumer.ofTypeClosure.begin(), consumer.ofTypeClosure.end(), eventTypeId) !=
         consumer.ofTypeClosure.end();
}

// ---- Lifecycle / observability ----

void EventSubscriberImpl::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [work = [self = weak_from_this(), callback = std::move(callback)]() mutable
      {
        auto strong = self.lock();
        if (!strong)
        {
          callback(VoidResult{});
          return;
        }
        strong->mClosing = true;
        strong->mConsumers.clear();
        strong->mTrackerHooks.clear();
        for (auto& backbone : strong->mBackbones)
        {
          backbone.consumers.clear();
          backbone.trackers.clear();
          backbone.pendingFirstEvent.clear();
        }
        strong->refresh_info_snapshot();
        boost::asio::post(strong->mExecutor,
          ua::async::guarded(
            strong->mLogger, [callback = std::move(callback)]() mutable { callback(VoidResult{}); }));
      }](auto&) mutable { work(); })();
}

std::shared_ptr<AlarmConditionTrackerImpl> EventSubscriberImpl::ensure_alarm_tracker(
  std::weak_ptr<WireOps> wireOps, AlarmConditionTrackerPolicy policy)
{
  std::call_once(mAlarmTrackerOnce,
    [this, &wireOps, &policy]
    {
      mAlarmTracker = AlarmConditionTrackerImpl::create(
        mStrand, mExecutor, weak_from_this(), std::move(wireOps), mLogger, policy, mObserverSink);
      // Attach the hook + arm initial refresh on the strand; fire-and-forget (the handle drives usage).
      mAlarmTracker->start_async([](ua::VoidResult) {});
    });
  return mAlarmTracker;
}

std::shared_ptr<const EventSubscriberInfo> EventSubscriberImpl::info() const noexcept
{
  return mInfoSnapshot.load();
}

void EventSubscriberImpl::deliver_void(std::function<void(ua::VoidResult)> callback, ua::VoidResult result)
{
  if (!callback)
  {
    return;
  }
  boost::asio::post(mExecutor,
    ua::async::guarded(mLogger, [callback = std::move(callback), result]() mutable { callback(result); }));
}

void EventSubscriberImpl::refresh_info_snapshot()
{
  std::size_t trackerCount = 0;
  for (const auto& weak : mTrackerHooks)
  {
    if (!weak.expired())
    {
      ++trackerCount;
    }
  }
  std::size_t backboneCount = 0;
  for (const auto& backbone : mBackbones)
  {
    if (backbone.created)
    {
      ++backboneCount;
    }
  }
  auto subscriberInfo = std::make_shared<EventSubscriberInfo>();
  subscriberInfo->backboneCount = backboneCount;
  subscriberInfo->consumerCount = mConsumers.size();
  subscriberInfo->trackerCount = trackerCount;
  subscriberInfo->lastPublishEventFieldListCount = mLastPublishFieldListCount;
  mInfoSnapshot.store(std::move(subscriberInfo));
}

}  // namespace ua::client::detail
