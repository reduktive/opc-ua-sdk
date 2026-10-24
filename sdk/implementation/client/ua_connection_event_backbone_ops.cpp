// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the real @ref ua::client::detail::EventBackboneOps shim (section 8.13): forwards
/// the
///        three backbone wire operations to @ref ua::client::detail::ConnectionImpl.

#include "ua_connection_event_backbone_ops.h"

#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_client_answer_status.h"
#include "ua_connection_impl.h"
#include "ua_error_detail.h"
#include "ua_modify_monitored_items_request.h"
#include "ua_modify_monitored_items_response.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitoring_parameters.h"
#include "ua_node_class.h"
#include "ua_status.h"

#include <algorithm>
#include <memory>
#include <utility>

namespace ua::client::detail
{

namespace
{
using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;

/// NS0 i=45, the HasSubtype ReferenceType that defines the whole type hierarchy (OPC 10000-5 Annex A).
constexpr std::uint32_t hasSubtypeReferenceType = 45U;

ua::Result<EventBackboneCreated> connection_gone_created()
{
  return ua::Result<EventBackboneCreated>{StatusCode{Status::BadConnectionClosed},
    ua::make_error_detail("BadConnectionClosed",
      "EventSubscriber backbone: Connection gone",
      "client.tier2.event_backbone.connection_gone")};
}
}  // namespace

EventFilterDiagnostics bad_event_filter_diagnostics(const ua::EventFilterResult& result)
{
  EventFilterDiagnostics diagnostics;
  for (std::size_t index = 0; index < result.select_clause_results().size(); ++index)
  {
    const auto status = result.select_clause_results()[index];
    if (status.is_bad())
    {
      diagnostics.push_back(EventFilterDiagnostic{EventFilterDiagnosticKind::SelectClause, index, 0, status});
    }
  }
  const auto& elementResults = result.where_clause_result().element_results();
  for (std::size_t elementIndex = 0; elementIndex < elementResults.size(); ++elementIndex)
  {
    const auto& elementResult = elementResults[elementIndex];
    if (elementResult.status_code().is_bad())
    {
      diagnostics.push_back(EventFilterDiagnostic{
        EventFilterDiagnosticKind::WhereClauseElement, elementIndex, 0, elementResult.status_code()});
    }
    for (std::size_t operandIndex = 0; operandIndex < elementResult.operand_status_codes().size();
         ++operandIndex)
    {
      const auto status = elementResult.operand_status_codes()[operandIndex];
      if (status.is_bad())
      {
        diagnostics.push_back(EventFilterDiagnostic{
          EventFilterDiagnosticKind::WhereClauseOperand, elementIndex, operandIndex, status});
      }
    }
  }
  return diagnostics;
}

std::shared_ptr<ConnectionEventBackboneOps> ConnectionEventBackboneOps::create(
  std::weak_ptr<ConnectionImpl> connection)
{
  return std::shared_ptr<ConnectionEventBackboneOps>(new ConnectionEventBackboneOps(std::move(connection)));
}

ConnectionEventBackboneOps::ConnectionEventBackboneOps(std::weak_ptr<ConnectionImpl> connection)
  : mConnection(std::move(connection))
{}

void ConnectionEventBackboneOps::create_backbone_async(ua::NodeId notifier, ua::EventFilter filter,
  std::uint32_t clientHandle, std::uint32_t queueSize,
  std::function<void(ua::Result<EventBackboneCreated>)> callback) noexcept
{
  auto connection = mConnection.lock();
  if (!connection)
  {
    callback(connection_gone_created());
    return;
  }
  // Create the backbone Subscription, then the event MonitoredItem on it.
  auto weak = weak_from_this();
  connection->create_subscription_async(0.0,
    [weak,
      notifier = std::move(notifier),
      filter = std::move(filter),
      clientHandle,
      queueSize,
      callback = std::move(callback)](ua::Result<std::uint32_t> subResult) mutable
    {
      if (!subResult.has_value())
      {
        callback(ua::Result<EventBackboneCreated>{subResult.status_code(), subResult.shared_detail()});
        return;
      }
      const StatusCode subscriptionStatus = subResult.status_code();
      auto self = weak.lock();
      if (!self)
      {
        callback(connection_gone_created());
        return;
      }
      const std::uint32_t subscriptionId = subResult.value();
      auto liveConnection = self->mConnection.lock();
      if (!liveConnection)
      {
        callback(connection_gone_created());
        return;
      }
      liveConnection->create_event_monitored_item_async(subscriptionId,
        std::move(notifier),
        clientHandle,
        std::move(filter),
        queueSize,
        [subscriptionId, subscriptionStatus, callback = std::move(callback)](
          ua::Result<EventBackboneCreated> miResult) mutable
        {
          if (!miResult.has_value())
          {
            callback(ua::Result<EventBackboneCreated>{miResult.status_code(), miResult.shared_detail()});
            return;
          }
          // A Good subcode or an Uncertain code on the Subscription's or the MonitoredItem's creation reaches
          // the caller.
          const StatusCode code = ua::detail::combined_status(subscriptionStatus, miResult.status_code());
          EventBackboneCreated created = std::move(miResult).value();
          created.subscriptionId = subscriptionId;
          callback(ua::detail::held(std::move(created), code));
        });
    });
}

void ConnectionEventBackboneOps::modify_backbone_filter_async(std::uint32_t subscriptionId,
  std::uint32_t monitoredItemId, std::uint32_t clientHandle, ua::EventFilter filter,
  std::function<void(ua::Result<EventFilterDiagnostics>)> callback) noexcept
{
  auto connection = mConnection.lock();
  if (!connection)
  {
    callback(ua::Result<EventFilterDiagnostics>{StatusCode{Status::BadConnectionClosed},
      ua::make_error_detail("BadConnectionClosed",
        "EventSubscriber modify filter: Connection gone",
        "client.tier2.event_backbone.connection_gone")});
    return;
  }

  ua::MonitoringParameters parameters;
  parameters.client_handle() = clientHandle;
  parameters.sampling_interval() = 0.0;
  parameters.queue_size() = 1;
  parameters.discard_oldest() = true;
  parameters.filter() = std::make_unique<ua::EventFilter>(std::move(filter));

  ua::MonitoredItemModifyRequest itemToModify;
  itemToModify.monitored_item_id() = monitoredItemId;
  itemToModify.requested_parameters() = std::move(parameters);

  ua::ModifyMonitoredItemsRequest request;
  request.subscription_id() = subscriptionId;
  request.timestamps_to_return() = ua::TimestampsToReturn::Both;
  request.items_to_modify().push_back(std::move(itemToModify));

  connection->modify_monitored_items_async(std::move(request),
    [callback = std::move(callback)](ua::Result<ua::ModifyMonitoredItemsResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<EventFilterDiagnostics>{result.status_code(), result.shared_detail()});
        return;
      }
      const auto& response = result.value();
      const auto serviceResult =
        ua::detail::combined_status(result.status_code(), response.response_header().service_result());
      if (serviceResult.is_bad())
      {
        callback(ua::Result<EventFilterDiagnostics>{serviceResult});
        return;
      }
      if (response.results().size() != 1)
      {
        callback(ua::Result<EventFilterDiagnostics>{StatusCode{Status::BadUnexpectedError},
          ua::make_error_detail("ModifyEventMonitoredItemResultCountMismatch",
            "the server returned a result count other than one for one event monitored item",
            "client.tier1.event_backbone.modify.result_count_mismatch")});
        return;
      }
      const auto& itemResult = response.results()[0];
      if (itemResult.status_code().is_bad())
      {
        callback(ua::Result<EventFilterDiagnostics>{
          itemResult.status_code(), itemResult.status_code().shared_detail()});
        return;
      }
      const auto* filterResult = dynamic_cast<const ua::EventFilterResult*>(itemResult.filter_result().get());
      // A Good subcode or an Uncertain code on the ServiceResult or the item's result reaches the caller.
      callback(ua::detail::held(
        filterResult == nullptr ? EventFilterDiagnostics{} : bad_event_filter_diagnostics(*filterResult),
        ua::detail::combined_status(serviceResult, itemResult.status_code())));
    });
}

void ConnectionEventBackboneOps::delete_backbone_async(std::uint32_t subscriptionId,
  std::uint32_t monitoredItemId, std::function<void(ua::VoidResult)> callback) noexcept
{
  auto connection = mConnection.lock();
  if (!connection)
  {
    callback(VoidResult{StatusCode{Status::BadConnectionClosed}});
    return;
  }
  // Delete the event MI, then delete its Subscription (the backbone is a Subscription-per-MI).
  auto weak = weak_from_this();
  connection->delete_monitored_item_async(subscriptionId,
    monitoredItemId,
    /*clientHandle=*/0,
    [weak, subscriptionId, callback = std::move(callback)](
      ua::Result<ua::DeleteMonitoredItemsResponse> /*miResult*/) mutable
    {
      auto self = weak.lock();
      if (!self)
      {
        callback(VoidResult{});
        return;
      }
      auto liveConnection = self->mConnection.lock();
      if (!liveConnection)
      {
        callback(VoidResult{});
        return;
      }
      liveConnection->delete_subscription_async(subscriptionId,
        [callback = std::move(callback)](ua::Result<ua::DeleteSubscriptionsResponse> /*subResult*/) mutable
        { callback(VoidResult{}); });
    });
}

/// One in-flight subtype walk. Level-order: each Browse carries the whole current frontier, so the walk
/// costs one round-trip per level of the hierarchy rather than one per type.
struct ConnectionEventBackboneOps::SubtypeWalk
{
  std::vector<ua::NodeId> frontier;  ///< the types whose subtypes this round asks for
  std::vector<ua::NodeId> closure;  ///< roots plus everything discovered so far (the result)
  std::size_t depth = 0;
  std::function<void(ua::Result<std::vector<ua::NodeId>>)> callback;
};

void ConnectionEventBackboneOps::resolve_event_subtypes_async(
  std::vector<ua::NodeId> roots, std::function<void(ua::Result<std::vector<ua::NodeId>>)> callback) noexcept
{
  if (roots.empty())
  {
    callback(ua::Result<std::vector<ua::NodeId>>{std::vector<ua::NodeId>{}});
    return;
  }
  auto walk = std::make_shared<SubtypeWalk>();
  walk->closure = roots;
  walk->frontier = std::move(roots);
  walk->callback = std::move(callback);
  continue_subtype_walk(shared_from_this(), std::move(walk));
}

void ConnectionEventBackboneOps::continue_subtype_walk(
  std::shared_ptr<ConnectionEventBackboneOps> self, std::shared_ptr<SubtypeWalk> walk)
{
  auto connection = self->mConnection.lock();
  if (!connection)
  {
    walk->callback(ua::Result<std::vector<ua::NodeId>>{StatusCode{Status::BadConnectionClosed},
      ua::make_error_detail("BadConnectionClosed",
        "EventSubscriber subtype resolution: Connection gone",
        "client.tier2.event_backbone.subtype_walk.connection_gone")});
    return;
  }
  if (walk->depth >= sMaxSubtypeDepth)
  {
    // Report rather than truncate: a partial closure silently drops the events it failed to enumerate,
    // which is the very failure this resolution exists to fix. The caller isolates the consumer instead.
    walk->callback(ua::Result<std::vector<ua::NodeId>>{StatusCode{Status::BadTooManyOperations},
      ua::make_error_detail("SubtypeWalkTooDeep",
        "event-type HasSubtype hierarchy exceeded the walk depth bound",
        "client.tier2.event_backbone.subtype_walk.depth_bound")});
    return;
  }

  ua::BrowseRequest request;
  for (const auto& node : walk->frontier)
  {
    ua::BrowseDescription browseDescription;
    browseDescription.node_id() = node;
    browseDescription.browse_direction() = ua::BrowseDirection::Forward;
    browseDescription.reference_type_id() = ua::NodeId{0, hasSubtypeReferenceType};
    browseDescription.include_subtypes() = false;  // HasSubtype itself, not references derived from it
    browseDescription.node_class_mask() = static_cast<std::uint32_t>(ua::NodeClass::ObjectType);
    request.nodes_to_browse().push_back(std::move(browseDescription));
  }

  connection->browse_async(std::move(request),
    [self, walk](ua::Result<ua::BrowseResponse> response) mutable
    {
      // The closure is built from these References, so an Uncertain answer at any layer is refused as a Bad
      // one is; a Good subcode is consumed.
      if (!response.is_good())
      {
        const StatusCode refused = answer_refused(response.status_code(),
          "ReferencesAnswerUncertain",
          "client.tier2.event_backbone.subtype_walk.browse_failed");
        walk->callback(ua::Result<std::vector<ua::NodeId>>{refused,
          ua::make_error_detail("SubtypeBrowseFailed",
            "Browse HasSubtype failed while resolving the event-type closure",
            "client.tier2.event_backbone.subtype_walk.browse_failed",
            refused)});
        return;
      }
      const auto serviceResult = response.value().response_header().service_result();
      if (!serviceResult.is_good())
      {
        const StatusCode refused = answer_refused(serviceResult,
          "ReferencesAnswerUncertain",
          "client.tier2.event_backbone.subtype_walk.service_fault");
        walk->callback(ua::Result<std::vector<ua::NodeId>>{refused,
          ua::make_error_detail("SubtypeBrowseServiceFault",
            "Browse HasSubtype returned a service fault while resolving the event-type closure",
            "client.tier2.event_backbone.subtype_walk.service_fault",
            refused)});
        return;
      }

      std::vector<ua::NodeId> nextFrontier;
      for (const auto& result : response.value().results())
      {
        // A per-node bad status means that branch of the hierarchy is unreadable. Treat it as fatal for
        // the closure for the same reason as the depth bound: an unreadable branch is exactly where the
        // missing subtypes would be.
        if (!result.status_code().is_good())
        {
          const StatusCode refused = answer_refused(result.status_code(),
            "ReferencesAnswerUncertain",
            "client.tier2.event_backbone.subtype_walk.node_failed");
          walk->callback(ua::Result<std::vector<ua::NodeId>>{refused,
            ua::make_error_detail("SubtypeBrowseNodeFailed",
              "a node in the event-type hierarchy could not be browsed",
              "client.tier2.event_backbone.subtype_walk.node_failed",
              refused)});
          return;
        }
        for (const auto& reference : result.references())
        {
          const auto& target = reference.node_id().node_id();
          if (target.is_null() || reference.node_id().server_index() != 0)
          {
            continue;  // a remote-server target is not a type this client can demux against
          }
          if (std::find(walk->closure.begin(), walk->closure.end(), target) != walk->closure.end())
          {
            continue;  // already known (a diamond in the hierarchy, or a cycle)
          }
          if (walk->closure.size() >= sMaxSubtypeNodes)
          {
            walk->callback(ua::Result<std::vector<ua::NodeId>>{StatusCode{Status::BadTooManyOperations},
              ua::make_error_detail("SubtypeWalkTooLarge",
                "event-type HasSubtype hierarchy exceeded the closure size bound",
                "client.tier2.event_backbone.subtype_walk.size_bound")});
            return;
          }
          walk->closure.push_back(target);
          nextFrontier.push_back(target);
        }
      }

      if (nextFrontier.empty())
      {
        walk->callback(ua::Result<std::vector<ua::NodeId>>{std::move(walk->closure)});
        return;
      }
      walk->frontier = std::move(nextFrontier);
      ++walk->depth;
      continue_subtype_walk(self, walk);
    });
}

}  // namespace ua::client::detail
