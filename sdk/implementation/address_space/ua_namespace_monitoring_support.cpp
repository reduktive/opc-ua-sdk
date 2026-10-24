// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_monitoring_support.h"
#include "ua_access_level_ex_type.h"
#include "ua_callback_safety.h"
#include "ua_data_access_utils.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace.h"
#include "ua_namespace_monitoring_support_access.h"
#include "ua_namespace_route.h"
#include "ua_node_description.h"
#include "ua_numeric_range_parser.h"
#include "ua_on_strand.h"
#include "ua_request_info.h"
#include "ua_sampling_engine.h"
#include "ua_to_string.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <numeric>

namespace ua::default_ns
{

namespace
{

StatusCode not_registered(string_view operation)
{
  return StatusCode{Status::BadNotSupported,
    ErrorDetail::build("NamespaceNotRegistered",
      "The namespace is not registered with an address space, so it has no monitoring helper yet",
      "NamespaceMonitoringSupport")
      .context(ua::ContextKeys::method, std::string{operation})};
}

StatusCode shut_down(string_view operation)
{
  return StatusCode{Status::BadShutdown,
    ErrorDetail::build("MonitoringShutDown",
      "The address space has shut this namespace's monitoring down",
      "NamespaceMonitoringSupport")
      .context(ua::ContextKeys::method, std::string{operation})};
}

/// What an item on the Value takes from its Node's description (NR-32 rule 3).
struct ValueDescription
{
  /// The MinimumSamplingInterval; 0 when the Node has none.
  Duration minimumSamplingInterval{0};
  /// The NodeClass: a Variable's Value is read through the namespace, a VariableType's from the description.
  NodeClass nodeClass{NodeClass::Variable};
};

ValueDescription describe_value(const Node& node)
{
  ValueDescription described;
  try
  {
    const auto nodeDescription = node.attributes();
    described.minimumSamplingInterval = nodeDescription.minimum_sampling_interval().value_or(0);
    described.nodeClass = nodeDescription.node_class();
  }
  catch (...)
  {
    // No description: no lower bound, and the Value is read through the namespace, which answers for it.
    ua::detail::ignore_expected_exception();
  }
  return described;
}

/// The engine's reader over the registered namespace (NR-47 rule 5, NR-49 rule 1): one call of
/// `read_values_async` for one caller's items, split by @p maxNodesPerRead as it answers at the tick, through
/// the route's guards (a throw, a second answer or an answer of another size fail that call's items with
/// `Bad_InternalError`). The first call starts on an executor turn of its own and every answer is posted, so
/// a namespace that answers inline gives the thread back between calls (DL-69 (D8)). Both posts are guarded:
/// a throw out of them is logged through @p logger, not let out of the executor. Completes with nullopt when
/// the namespace is gone.
SamplingEngine::ValueReader namespace_reader(boost::asio::any_io_executor executor, ua::Logger logger,
  std::weak_ptr<ua::Namespace> owner, std::function<std::optional<uint32_t>()> maxNodesPerRead)
{
  using Reads = std::vector<SamplingEngine::ValueRead>;
  using Complete = std::function<void(std::optional<std::vector<DataValueResult>>)>;
  using Route = ua::detail::NamespaceRoute<DataValueResult>;
  using Answer = std::function<void(BatchResult<DataValueResult>)>;
  return [executor = std::move(executor),
           logger = std::move(logger),
           owner = std::move(owner),
           maxNodesPerRead = std::move(maxNodesPerRead)](
           std::shared_ptr<const CallerInfo> caller, Reads items, Complete complete)
  {
    auto registered = owner.lock();
    if (!registered)
    {
      complete(std::nullopt);
      return;
    }

    // Held until every call has answered: the Nodes and ReadValueIds the items refer to, and the caller
    // (NR-49 rule 4).
    struct State
    {
      Reads items;
      std::shared_ptr<const CallerInfo> caller;
    };
    auto state = std::make_shared<State>(State{std::move(items), std::move(caller)});
    std::vector<std::optional<DataValueResult>> answers(state->items.size());
    std::vector<size_t> everyItem(state->items.size());
    std::iota(everyItem.begin(), everyItem.end(), size_t{0});
    std::vector<Route::Part> parts;
    parts.push_back(Route::Part{std::move(registered), std::move(everyItem)});
    const std::optional<uint32_t> limit = maxNodesPerRead ? maxNodesPerRead() : std::nullopt;

    boost::asio::post(executor,
      ua::async::guarded(logger,
        [executor,
          logger,
          state,
          answers = std::move(answers),
          parts = std::move(parts),
          limit,
          complete = std::move(complete)]() mutable
        {
          Route::run(
            std::move(answers),
            std::move(parts),
            limit,
            [executor, logger, state](
              ua::Namespace& nameSpace, std::span<const size_t> positions, Answer answer)
            {
              std::vector<ValueReadItem> calls;
              calls.reserve(positions.size());
              for (const size_t position : positions)
              {
                calls.push_back(ValueReadItem{*state->items[position].node, state->items[position].value});
              }
              // The server's own request: no deadline, never cancelled (NR-46 rule 2).
              const RequestInfo request{};
              nameSpace.read_values_async(request,
                state->caller.get(),
                calls,
                0,
                true,
                [executor, logger, answer = std::move(answer)](BatchResult<DataValueResult> batch)
                {
                  boost::asio::post(executor,
                    ua::async::guarded(
                      logger, [answer, batch = std::move(batch)]() mutable { answer(std::move(batch)); }));
                });
            },
            [complete = std::move(complete)](std::vector<DataValueResult> read)
            { complete(std::move(read)); });
        }));
  };
}

}  // namespace

NamespaceMonitoringSupport::NamespaceMonitoringSupport() = default;

NamespaceMonitoringSupport::NamespaceMonitoringSupport(boost::asio::any_io_executor executor,
  ua::Logger logger, std::weak_ptr<ua::Namespace> owner,
  std::function<std::optional<uint32_t>()> maxNodesPerRead)
  : mEngine(std::make_shared<SamplingEngine>(
      executor, namespace_reader(executor, logger, std::move(owner), std::move(maxNodesPerRead)), logger))
{}

NamespaceMonitoringSupport::~NamespaceMonitoringSupport()
{
  if (mEngine)
  {
    mEngine->shutdown();
  }
}

std::vector<NamespaceMonitoringSupport::CreateResult> NamespaceMonitoringSupport::create_monitoring(
  std::span<const ResolvedMonitoringItem> items)
{
  std::vector<CreateResult> results;
  results.reserve(items.size());

  // Engine calls happen outside the helper's mutex - the engine has its own. mRecords and mNextHandle
  // change under mMutex (8.2 hazard 1).
  for (const auto& resolved : items)
  {
    CreateResult cr;
    const auto& item = resolved.item;

    if (!mEngine)
    {
      // Before registration, and before the item's Node is looked at.
      cr.result = MonitoringCreateItemResult{not_registered("create_monitoring")};
      results.push_back(std::move(cr));
      continue;
    }
    {
      const std::lock_guard lock{mMutex};
      if (mShutDown)
      {
        cr.result = MonitoringCreateItemResult{shut_down("create_monitoring")};
        results.push_back(std::move(cr));
        continue;
      }
    }

    const auto& node = item.node;
    if (!node)
    {
      cr.result = MonitoringCreateItemResult{StatusCode{Status::BadNodeIdUnknown,
        ErrorDetail::build(
          "NodeIdUnknown", "Monitored item target node does not exist", "NamespaceMonitoringSupport")
          .context(ua::ContextKeys::nodeId, to_string(item.nodeId))
          .context(ua::ContextKeys::monitoredItemId, std::to_string(item.monitoredItemId))}};
      results.push_back(std::move(cr));
      continue;
    }

    // Parsed once, here: every value the registration delivers is narrowed to it (NR-14 rule 1, NR-48 rule
    // 2). A range that does not parse is refused with the parser's answer rather than ignored.
    auto range = parse_numeric_range(item.indexRange);
    if (!range.is_good())
    {
      cr.result = MonitoringCreateItemResult{range.status_code()};
      results.push_back(std::move(cr));
      continue;
    }

    // Part 4 5.12.1.2: a Value item is served no faster than the Node's MinimumSamplingInterval, however
    // the server learns of a change - read at the tick or reported by the namespace.
    const ValueDescription described =
      item.attributeId == AttributeId::Value ? describe_value(*node) : ValueDescription{};
    const Duration interval = item.attributeId == AttributeId::Value
                                ? std::max(item.samplingInterval, described.minimumSamplingInterval)
                                : item.samplingInterval;

    SamplingEngine::AddResult added;
    if (resolved.delivery == Delivery::Sampled)
    {
      SamplingEngine::PolledRegistration reg;
      reg.node = node;
      reg.nodeClass = described.nodeClass;
      reg.nodeId = item.nodeId;
      reg.attributeId = item.attributeId;
      reg.indexRange = item.indexRange;
      reg.range = std::move(range).value();
      reg.monitoredItemId = item.monitoredItemId;
      reg.requestedInterval = interval;
      reg.sink = item.sink;
      added = mEngine->add_polled(std::move(reg));
    }
    else
    {
      SamplingEngine::ExceptionRegistration reg;
      reg.node = node;
      reg.nodeClass = described.nodeClass;
      reg.nodeId = item.nodeId;
      reg.attributeId = item.attributeId;
      reg.indexRange = item.indexRange;
      reg.range = std::move(range).value();
      reg.monitoredItemId = item.monitoredItemId;
      reg.requestedInterval = interval;
      reg.queueSize = item.queueSize;
      reg.sink = item.sink;
      added = (item.attributeId == AttributeId::Value && interval == 0)
                ? mEngine->add_exception_queued(std::move(reg))
                : mEngine->add_exception_latest(std::move(reg));
    }

    if (added.handle == 0)
    {
      // The engine was shut down between the check above and the add.
      cr.result = MonitoringCreateItemResult{shut_down("create_monitoring")};
      results.push_back(std::move(cr));
      continue;
    }

    MonitoringHandle nsHandle = 0;
    {
      const std::lock_guard lock{mMutex};
      nsHandle = ua::detail::issue_handle(
        mNextHandle, [this](MonitoringHandle candidate) { return mRecords.contains(candidate); });
      mRecords[nsHandle] = Record{added.handle, node, item.attributeId, resolved.delivery};
    }

    cr.result = MonitoringCreateItemResult{
      MonitoringCreateSuccess{.handle = nsHandle, .revisedSamplingInterval = added.revisedInterval}};
    results.push_back(std::move(cr));
  }

  return results;
}

std::vector<NamespaceMonitoringSupport::ModifyResult> NamespaceMonitoringSupport::modify_monitoring(
  std::span<const ResolvedMonitoringModifyItem> items)
{
  std::vector<ModifyResult> results;
  results.reserve(items.size());

  for (const auto& resolved : items)
  {
    ModifyResult mr;
    const auto& item = resolved.item;

    if (!mEngine)
    {
      mr.result = MonitoringModifyItemResult{not_registered("modify_monitoring")};
      results.push_back(std::move(mr));
      continue;
    }

    Record record;
    {
      const std::lock_guard lock{mMutex};
      if (mShutDown)
      {
        mr.result = MonitoringModifyItemResult{shut_down("modify_monitoring")};
        results.push_back(std::move(mr));
        continue;
      }
      auto it = mRecords.find(item.handle);
      if (it == mRecords.end())
      {
        mr.result = MonitoringModifyItemResult{StatusCode{Status::BadMonitoredItemIdInvalid}};
        results.push_back(std::move(mr));
        continue;
      }
      record = it->second;
    }

    SamplingEngine::ModifyRegistration reg;
    reg.requestedInterval = item.samplingInterval;
    reg.queueSize = item.queueSize;
    reg.delivery = resolved.delivery;
    if (record.attributeId == AttributeId::Value)
    {
      // As on create, for either delivery (Part 4 5.12.1.2).
      if (const auto node = record.node.lock())
      {
        reg.requestedInterval =
          std::max(item.samplingInterval, describe_value(*node).minimumSamplingInterval);
      }
    }

    const auto modified = mEngine->modify(record.engineHandle, reg);

    {
      const std::lock_guard lock{mMutex};
      auto it = mRecords.find(item.handle);
      if (it != mRecords.end())
      {
        it->second.delivery = resolved.delivery;
      }
    }

    if (!modified.found)
    {
      // The tick that found the Node deleted erased the engine's entry; the registration stays, inactive,
      // until it is deleted, and the Subscription commits the revised parameters after this Good result.
      mr.result =
        MonitoringModifyItemResult{MonitoringModifySuccess{.revisedSamplingInterval = item.samplingInterval}};
      results.push_back(std::move(mr));
      continue;
    }

    mr.result = MonitoringModifyItemResult{
      MonitoringModifySuccess{.revisedSamplingInterval = modified.revisedInterval}};
    results.push_back(std::move(mr));
  }

  return results;
}

std::vector<VoidResult> NamespaceMonitoringSupport::delete_monitoring(
  std::span<const MonitoringHandle> handles)
{
  std::vector<VoidResult> results;
  results.reserve(handles.size());

  for (auto handle : handles)
  {
    if (!mEngine)
    {
      results.emplace_back(not_registered("delete_monitoring"));
      continue;
    }

    MonitoringHandle engineHandle{};
    bool found = false;
    {
      const std::lock_guard lock{mMutex};
      auto it = mRecords.find(handle);
      if (it != mRecords.end())
      {
        engineHandle = it->second.engineHandle;
        mRecords.erase(it);
        found = true;
      }
    }

    if (!found)
    {
      results.emplace_back(StatusCode{Status::BadMonitoredItemIdInvalid});
      continue;
    }

    // A no-op for an entry the tick erased when it found the Node deleted.
    mEngine->remove(engineHandle);
    results.emplace_back();
  }

  return results;
}

void NamespaceMonitoringSupport::attribute_changed(
  const NodeId& node, AttributeId attribute, const DataValue& value)
{
  if (mEngine)
  {
    mEngine->attribute_changed(node, attribute, value);
  }
}

void NamespaceMonitoringSupport::structure_changed(const NodeId& variable)
{
  if (!mEngine)
  {
    return;
  }
  // The engine copies the registrations out under its own mutex; the sinks are called with no lock held.
  // After shutdown the engine holds no registration, so nothing is marked.
  for (const auto& monitor : mEngine->find_monitors(variable, AttributeId::Value))
  {
    if (monitor.sink)
    {
      monitor.sink->mark_structure_changed(monitor.monitoredItemId);
    }
  }
}

bool NamespaceMonitoringSupport::property_value_changed(
  const NodeId& owner, const Node& property, bool initial)
{
  const NodeDescription nodeDescription = property.attributes();
  const AccessLevelExType accessLevelEx = nodeDescription.access_level_ex().value_or(AccessLevelExType{});
  if (mEngine)
  {
    // The BrowseName is read only when the owner's Value is monitored.
    const auto monitors = mEngine->find_monitors(owner, AttributeId::Value);
    if (!monitors.empty() &&
        data_access_utils::is_semantic_property(nodeDescription.browse_name(), accessLevelEx))
    {
      for (const auto& monitor : monitors)
      {
        if (monitor.sink)
        {
          monitor.sink->mark_semantics_changed(monitor.monitoredItemId);
        }
      }
    }
  }
  return accessLevelEx.test(AccessLevelExType::Bit::SemanticChange) && !initial;
}

}  // namespace ua::default_ns

namespace ua::detail
{

std::shared_ptr<MonitoringSupportAccess::Helper> MonitoringSupportAccess::create(
  boost::asio::any_io_executor executor, Logger logger, std::weak_ptr<Namespace> owner,
  std::function<std::optional<uint32_t>()> maxNodesPerRead)
{
  return std::shared_ptr<Helper>(
    new Helper(std::move(executor), std::move(logger), std::move(owner), std::move(maxNodesPerRead)));
}

std::shared_ptr<MonitoringSupportAccess::Helper> MonitoringSupportAccess::create_unattached()
{
  return std::shared_ptr<Helper>(new Helper());
}

void MonitoringSupportAccess::shutdown_async(Helper& helper, std::function<void()> done) noexcept
{
  try
  {
    {
      const std::lock_guard lock{helper.mMutex};
      helper.mShutDown = true;
    }
    if (helper.mEngine)
    {
      helper.mEngine->shutdown_async(std::move(done));
      return;
    }
  }
  catch (...)
  {
    // shutdown_async allocates only to park @p done; were that to fail, the helper is still stopped
    // (its timers cancelled, its flag set), and the caller is answered rather than left waiting.
    ignore_expected_exception();
  }
  if (done)
  {
    invoke_user_callback(done);
  }
}

std::optional<MonitoringSupportAccess::Registration> MonitoringSupportAccess::registration(
  const Helper& helper, MonitoringHandle handle)
{
  const std::lock_guard lock{helper.mMutex};
  auto it = helper.mRecords.find(handle);
  if (it == helper.mRecords.end())
  {
    return std::nullopt;
  }
  return Registration{it->second.node.lock(), it->second.attributeId, it->second.delivery};
}

}  // namespace ua::detail
